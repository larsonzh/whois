// SPDX-License-Identifier: MIT
// lookup_exec_start.h - Start host/label resolution for lookup exec
#ifndef WC_LOOKUP_EXEC_START_H_
#define WC_LOOKUP_EXEC_START_H_

#include <stddef.h>

struct Config;
struct wc_query;

int wc_lookup_exec_resolve_start(const struct wc_query* q,
                                 const struct Config* cfg,
                                 char* start_host,
                                 size_t start_host_len,
                                 char* start_label,
                                 size_t start_label_len);

#endif // WC_LOOKUP_EXEC_START_H_
