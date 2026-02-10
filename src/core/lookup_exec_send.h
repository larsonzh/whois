// SPDX-License-Identifier: MIT
// lookup_exec_send.h - Query build/send for lookup exec
#ifndef WC_LOOKUP_EXEC_SEND_H_
#define WC_LOOKUP_EXEC_SEND_H_

#include <stddef.h>

#include "wc/wc_lookup.h"

struct Config;
struct wc_net_context;
struct wc_net_info;

struct wc_lookup_exec_send_ctx {
    struct wc_result* out;
    const struct wc_query* q;
    const struct wc_lookup_opts* zopts;
    const struct Config* cfg;
    const struct wc_net_context* net_ctx;
    const char* current_host;
    int arin_host;
    int query_is_cidr_effective;
    int query_is_ip_literal_effective;
    int query_is_ip_literal;
    int query_is_cidr;
    int query_is_asn;
    int query_is_nethandle;
    int query_has_arin_prefix;
    const char* cidr_base_query;
    int use_original_query;

    char** arin_cidr_retry_query;
    struct wc_net_info* ni;
    int* pending_referral;
};

int wc_lookup_exec_send_query(struct wc_lookup_exec_send_ctx* ctx);

#endif // WC_LOOKUP_EXEC_SEND_H_
