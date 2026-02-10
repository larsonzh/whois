// SPDX-License-Identifier: MIT
// lookup_exec_visit.c - Visited host tracking helpers

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "wc/wc_dns.h"
#include "lookup_internal.h"
#include "lookup_exec_visit.h"

static char* wc_lookup_exec_xstrdup(const char* s)
{
    if (!s) {
        return NULL;
    }
    size_t n = strlen(s) + 1;
    char* p = (char*)malloc(n);
    if (!p) {
        return NULL;
    }
    memcpy(p, s, n);
    return p;
}

void wc_lookup_exec_mark_visited(const char* current_host,
                                 char** visited,
                                 int* visited_count)
{
    if (!current_host || !visited || !visited_count) {
        return;
    }

    int already = 0;
    for (int i = 0; i < *visited_count; ++i) {
        if (strcasecmp(visited[i], current_host) == 0) {
            already = 1;
            break;
        }
    }
    if (!already && *visited_count < 16) {
        visited[(*visited_count)++] = wc_lookup_exec_xstrdup(current_host);
    }

    if (wc_dns_is_ip_literal(current_host)) {
        const char* mapped_host = wc_lookup_known_ip_host_from_literal(current_host);
        if (mapped_host && *mapped_host &&
            !wc_lookup_visited_has(visited, *visited_count, mapped_host) && *visited_count < 16) {
            visited[(*visited_count)++] = wc_lookup_exec_xstrdup(mapped_host);
        }
    }

    const char* canon_visit = wc_dns_canonical_alias(current_host);
    if (canon_visit && canon_visit[0] && strcasecmp(canon_visit, current_host) != 0) {
        if (!wc_lookup_visited_has(visited, *visited_count, canon_visit) && *visited_count < 16) {
            visited[(*visited_count)++] = wc_lookup_exec_xstrdup(canon_visit);
        }
    }
}
