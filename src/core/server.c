// SPDX-License-Identifier: MIT
// server.c - Phase A skeleton for whois server normalization and RIR guess
#include <string.h>
#include <ctype.h>
#include "wc/wc_server.h"

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
    return "unknown";
}
