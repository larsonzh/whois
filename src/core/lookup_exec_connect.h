// SPDX-License-Identifier: MIT
// lookup_exec_connect.h - Dial + DNS candidate handling for lookup exec
#ifndef WC_LOOKUP_EXEC_CONNECT_H_
#define WC_LOOKUP_EXEC_CONNECT_H_

#include <stddef.h>

#include "wc/wc_lookup.h"

struct Config;
struct wc_net_context;
struct wc_net_info;

struct wc_lookup_exec_connect_ctx {
    struct wc_result* out;
    const struct wc_lookup_opts* zopts;
    const struct Config* cfg;
    struct wc_net_context* net_ctx;
    const char* current_host;
    int hops;
    int current_port;
    int query_is_ipv4_literal_effective;
    struct Config* cfg_override;
    const struct Config** cfg_for_dns;
    int* hop_prefers_v4;
    int* arin_host;
    char* canonical_host;
    size_t canonical_host_len;
    char* pref_label;
    size_t pref_label_len;
    struct wc_net_info* ni;
    int* connected_ok;
    int* first_conn_rc;
    int* attempt_cap_hit;
};

int wc_lookup_exec_connect(struct wc_lookup_exec_connect_ctx* ctx);

#endif // WC_LOOKUP_EXEC_CONNECT_H_
