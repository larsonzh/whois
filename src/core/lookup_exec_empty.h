// SPDX-License-Identifier: MIT
// lookup_exec_empty.h - Empty-body handling for lookup exec
#ifndef WC_LOOKUP_EXEC_EMPTY_H_
#define WC_LOOKUP_EXEC_EMPTY_H_

#include <stddef.h>

#include "wc/wc_lookup.h"

struct Config;
struct wc_net_context;
struct wc_net_info;

struct wc_lookup_exec_empty_ctx {
    struct wc_result* out;
    const struct wc_query* q;
    const struct wc_lookup_opts* zopts;
    const struct Config* cfg;
    const struct Config* cfg_for_dns;
    struct wc_net_context* net_ctx;
    const char* current_host;
    const char* canonical_host;
    const char* pref_label;
    int hops;
    int hop_prefers_v4;
    int current_port;
    int* empty_retry;
    struct wc_net_info* ni;
    char** body;
    size_t* blen;
    int* persistent_empty;
};

int wc_lookup_exec_handle_empty_body(struct wc_lookup_exec_empty_ctx* ctx);

#endif // WC_LOOKUP_EXEC_EMPTY_H_
