// SPDX-License-Identifier: MIT
// lookup_exec_recv.h - Receive body for lookup exec
#ifndef WC_LOOKUP_EXEC_RECV_H_
#define WC_LOOKUP_EXEC_RECV_H_

#include <stddef.h>

struct Config;
struct wc_lookup_opts;
struct wc_net_info;
struct wc_result;

struct wc_lookup_exec_recv_ctx {
    struct wc_result* out;
    const struct wc_lookup_opts* zopts;
    const struct Config* cfg;
    struct wc_net_info* ni;
    int* pending_referral;
    char** body;
    size_t* blen;
};

int wc_lookup_exec_recv_body(struct wc_lookup_exec_recv_ctx* ctx);

#endif // WC_LOOKUP_EXEC_RECV_H_
