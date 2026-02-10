// SPDX-License-Identifier: MIT
// lookup_exec_post.h - Post-loop finalize and cleanup
#ifndef WC_LOOKUP_EXEC_POST_H_
#define WC_LOOKUP_EXEC_POST_H_

#include <stddef.h>

struct Config;
struct wc_lookup_opts;
struct wc_net_context;
struct wc_query;
struct wc_result;

struct wc_lookup_exec_post_ctx {
    struct wc_result* out;
    const struct wc_query* q;
    const struct wc_lookup_opts* zopts;
    const struct Config* cfg;
    struct wc_net_context* net_ctx;

    const char* start_host;
    const char* start_label;
    const char* current_host;

    char** combined;
    int redirect_cap_hit;
    int last_hop_authoritative;
    int last_hop_need_redirect;
    int last_hop_has_ref;

    int apnic_erx_root;
    int apnic_erx_seen_arin;
    int apnic_redirect_is_erx;
    int erx_marker_seen;
    int rir_cycle_exhausted;
    int saw_rate_limit_or_denied;
    int erx_baseline_recheck_attempted;
    const char* erx_marker_host;
    const char* erx_marker_ip;
    const char* apnic_erx_root_host;
    const char* apnic_erx_root_ip;
    const char* apnic_last_ip;

    int query_is_cidr_effective;
    char** cidr_base_query;
    char** arin_cidr_retry_query;

    char** visited;
    int visited_count;
    int visited_len;

    int* failure_emitted;
    char* last_failure_host;
    size_t last_failure_host_len;
    char* last_failure_ip;
    size_t last_failure_ip_len;
    char* last_failure_rir;
    size_t last_failure_rir_len;
    const char* last_failure_status;
    const char* last_failure_desc;
};

int wc_lookup_exec_post_finalize(struct wc_lookup_exec_post_ctx* ctx);

#endif // WC_LOOKUP_EXEC_POST_H_
