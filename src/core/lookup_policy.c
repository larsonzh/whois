// SPDX-License-Identifier: MIT
// lookup_policy.c - RIR cycle and ERX policy helpers for lookup
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#include <string.h>
#include <strings.h>
#include <stdio.h>

#include "wc/wc_dns.h"
#include "lookup_internal.h"

static int wc_lookup_erx_baseline_recheck_guard = 0;

int wc_lookup_erx_baseline_recheck_guard_get(void) {
    return wc_lookup_erx_baseline_recheck_guard;
}

void wc_lookup_erx_baseline_recheck_guard_set(int value) {
    wc_lookup_erx_baseline_recheck_guard = value ? 1 : 0;
}

int wc_lookup_rir_cycle_next(const char* current_rir,
                             char** visited,
                             int visited_count,
                             char* out,
                             size_t outlen) {
    (void)current_rir;
    static const char* k_rir_cycle[] = {
        "apnic", "arin", "ripe", "afrinic", "lacnic", NULL
    };
    if (!out || outlen == 0) return 0;
    int count = 0;
    for (; k_rir_cycle[count]; ++count) { /* count */ }
    if (count == 0) return 0;

    int start_idx = 0; // always start from APNIC

    for (int i = 0; i < count; ++i) {
        int idx = (start_idx + i) % count;
        const char* rir = k_rir_cycle[idx];
        const char* host = wc_dns_canonical_host_for_rir(rir);
        if (!host || !*host) continue;
        int seen = 0;
        for (int v = 0; v < visited_count; ++v) {
            if (visited[v] && wc_lookup_hosts_match(visited[v], host)) {
                seen = 1;
                break;
            }
        }
        if (seen) continue;
        snprintf(out, outlen, "%s", host);
        return 1;
    }
    return 0;
}
