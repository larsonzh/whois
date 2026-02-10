// SPDX-License-Identifier: MIT
// lookup_exec_start.c - Start host/label resolution for lookup exec

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "wc/wc_config.h"
#include "wc/wc_dns.h"
#include "wc/wc_server.h"
#include "wc/wc_lookup.h"
#include "lookup_exec_start.h"

int wc_lookup_exec_resolve_start(const struct wc_query* q,
                                 const struct Config* cfg,
                                 char* start_host,
                                 size_t start_host_len,
                                 char* start_label,
                                 size_t start_label_len)
{
    if (!q || !start_host || !start_label || start_host_len == 0 || start_label_len == 0) {
        return -1;
    }

    if (q->start_server && q->start_server[0]) {
        const char* rir_guess = wc_guess_rir(q->start_server);
        const char* canon_label = NULL;
        if (rir_guess && strcmp(rir_guess, "unknown") != 0) {
            canon_label = wc_dns_canonical_host_for_rir(rir_guess);
        }
        if (!canon_label) {
            canon_label = wc_dns_canonical_host_for_rir(q->start_server);
        }
        char* mapped = NULL;
        if (!canon_label && wc_dns_is_ip_literal(q->start_server)) {
            mapped = wc_dns_rir_fallback_from_ip(cfg, q->start_server);
            if (mapped) {
                canon_label = mapped;
            }
        }

        if (canon_label) {
            snprintf(start_label, start_label_len, "%s", canon_label);
        } else {
            snprintf(start_label, start_label_len, "%s", q->start_server);
        }

        if (mapped) {
            free(mapped);
        }
    } else {
        snprintf(start_label, start_label_len, "%s", "whois.iana.org");
    }

    if (q->start_server && q->start_server[0]) {
        if (wc_normalize_whois_host(q->start_server, start_host, start_host_len) != 0) {
            snprintf(start_host, start_host_len, "%s", q->start_server);
        }
    } else {
        snprintf(start_host, start_host_len, "%s", "whois.iana.org");
    }

    return 0;
}
