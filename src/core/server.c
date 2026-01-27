// SPDX-License-Identifier: MIT
// server.c - Phase A skeleton for whois server normalization and RIR guess
#include <string.h>
#include <ctype.h>
#include "wc/wc_server.h"

static const char* const k_wc_server_default_batch_hosts[] = {
    "whois.iana.org",
    "whois.arin.net",
    "whois.ripe.net",
    "whois.apnic.net",
    "whois.lacnic.net",
    "whois.afrinic.net",
    "whois.verisign-grs.com",
};

static int ieq(const char* a, const char* b){ for(;*a && *b; a++,b++){ if(tolower((unsigned char)*a)!=tolower((unsigned char)*b)) return 0;} return *a==0 && *b==0; }

int wc_normalize_whois_host(const char* in, char* out, size_t cap) {
    if(!in||!out||cap==0) return -1;
    const char* canonical = in;
    // Simple alias examples (extend later)
    if (ieq(in, "whois.ripe.net") || ieq(in, "ripe")) canonical = "whois.ripe.net";
    else if (ieq(in, "whois.arin.net") || ieq(in, "arin")) canonical = "whois.arin.net";
    else if (ieq(in, "whois.apnic.net") || ieq(in, "apnic")) canonical = "whois.apnic.net";
    else if (ieq(in, "whois.lacnic.net") || ieq(in, "lacnic")) canonical = "whois.lacnic.net";
    else if (ieq(in, "whois.afrinic.net") || ieq(in, "afrinic")) canonical = "whois.afrinic.net";
    else if (ieq(in, "whois.iana.org") || ieq(in, "iana")) canonical = "whois.iana.org";
    else if (ieq(in, "whois.verisign-grs.com") || ieq(in, "verisign")) canonical = "whois.verisign-grs.com";
    size_t n = strlen(canonical);
    if (n+1 > cap) return -2;
    memcpy(out, canonical, n+1);
    return 0;
}

const char* wc_guess_rir(const char* host_or_ip) {
    if(!host_or_ip) return "unknown";
    // Quick host substring checks (placeholder heuristic)
    if (strstr(host_or_ip, "arin")) return "arin";
    if (strstr(host_or_ip, "ripe")) return "ripe";
    if (strstr(host_or_ip, "apnic")) return "apnic";
    if (strstr(host_or_ip, "lacnic")) return "lacnic";
    if (strstr(host_or_ip, "afrinic")) return "afrinic";
    if (strstr(host_or_ip, "iana")) return "iana";
    if (strstr(host_or_ip, "verisign")) return "verisign";
    // Known IP literals for major RIRs/IANA (helps when -h uses an IP)
    if (ieq(host_or_ip, "2001:500:13::46") || ieq(host_or_ip, "2001:500:a9::46")
        || ieq(host_or_ip, "2001:500:31::46")
        || ieq(host_or_ip, "199.71.0.46") || ieq(host_or_ip, "199.5.26.46")
        || ieq(host_or_ip, "199.212.0.46") || ieq(host_or_ip, "199.91.0.46")) {
        return "arin";
    }
    if (ieq(host_or_ip, "203.119.102.24") || ieq(host_or_ip, "203.119.102.29")
        || ieq(host_or_ip, "203.119.0.147") || ieq(host_or_ip, "207.148.30.186")
        || ieq(host_or_ip, "136.244.64.117") || ieq(host_or_ip, "202.12.28.136")
        || ieq(host_or_ip, "2001:dd8:8:701::24") || ieq(host_or_ip, "2001:dd8:8:701::29")
        || ieq(host_or_ip, "2001:dc0:c003::147") || ieq(host_or_ip, "2001:dc0:1:0:4777::136")
        || ieq(host_or_ip, "2001:19f0:5:3a2:5400:5ff:fe36:e789")
        || ieq(host_or_ip, "2001:19f0:7401:8fd4:5400:5ff:fe35:cb0a")) {
        return "apnic";
    }
    if (ieq(host_or_ip, "193.0.6.135") || ieq(host_or_ip, "2001:67c:2e8:22::c100:687")) {
        return "ripe";
    }
    if (ieq(host_or_ip, "190.112.52.16") || ieq(host_or_ip, "2001:13c7:7020:210::16")
        || ieq(host_or_ip, "168.121.184.15") || ieq(host_or_ip, "2001:13c7:7001:110::15")
        || ieq(host_or_ip, "168.121.184.16") || ieq(host_or_ip, "2001:13c7:7001:110::16")
        || ieq(host_or_ip, "168.121.184.28") || ieq(host_or_ip, "2001:13c7:7001:110::28")
        || ieq(host_or_ip, "168.121.184.41") || ieq(host_or_ip, "2001:13c7:7001:110::41")
        || ieq(host_or_ip, "200.3.14.137") || ieq(host_or_ip, "2001:13c7:7002:4128::137")
        || ieq(host_or_ip, "200.3.14.138") || ieq(host_or_ip, "2001:13c7:7002:4128::138")
        || ieq(host_or_ip, "200.3.14.139") || ieq(host_or_ip, "2001:13c7:7002:4128::139")
        || ieq(host_or_ip, "200.3.14.149") || ieq(host_or_ip, "2001:13c7:7002:4128::149")
        || ieq(host_or_ip, "200.3.14.150") || ieq(host_or_ip, "2001:13c7:7002:4128::150")
        || ieq(host_or_ip, "200.3.14.151") || ieq(host_or_ip, "2001:13c7:7002:4128::151")) {
        return "lacnic";
    }
    if (ieq(host_or_ip, "196.192.115.21") || ieq(host_or_ip, "2001:42d0:2:601::21")
        || ieq(host_or_ip, "196.192.115.22") || ieq(host_or_ip, "2001:42d0:2:601::22")
        || ieq(host_or_ip, "196.216.2.20") || ieq(host_or_ip, "2001:42d0:0:201::20")
        || ieq(host_or_ip, "196.216.2.21") || ieq(host_or_ip, "2001:42d0:0:201::21")) {
        return "afrinic";
    }
    if (ieq(host_or_ip, "192.0.32.59") || ieq(host_or_ip, "192.0.47.59")
        || ieq(host_or_ip, "2620:0:2d0:200::59") || ieq(host_or_ip, "2620:0:2830:200::59")) {
        return "iana";
    }
    if (ieq(host_or_ip, "2620:74:21::30") || ieq(host_or_ip, "2620:74:20::30") ||
        ieq(host_or_ip, "192.30.45.30") || ieq(host_or_ip, "192.34.234.30")) {
        return "verisign";
    }
    return "unknown";
}

const char* wc_server_default_batch_host(void)
{
    return k_wc_server_default_batch_hosts[0];
}

size_t wc_server_get_default_batch_hosts(const char* const** out)
{
    if (out)
        *out = k_wc_server_default_batch_hosts;
    return sizeof(k_wc_server_default_batch_hosts) / sizeof(k_wc_server_default_batch_hosts[0]);
}
