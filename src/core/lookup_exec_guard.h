// SPDX-License-Identifier: MIT
// lookup_exec_guard.h - Loop guard helpers for lookup exec
#ifndef WC_LOOKUP_EXEC_GUARD_H_
#define WC_LOOKUP_EXEC_GUARD_H_

#include <stddef.h>

struct wc_result;
struct wc_net_context;
struct wc_net_info;
struct Config;

struct wc_lookup_exec_guard_no_next_ctx {
    struct wc_result* out;
    const char* current_host;
    const char* current_rir_guess;
    const char* header_host;
    int header_is_iana;
    int auth;
    int apnic_erx_root;
    int query_is_cidr_effective;
    int seen_real_authoritative;
    int seen_apnic_iana_netblock;
    int seen_ripe_non_managed;
    int seen_afrinic_iana_blk;
    int seen_lacnic_unallocated;
    int seen_arin_no_match_cidr;

    int* have_next;
    char* next_host;
    size_t next_host_len;

    char** visited;
    int visited_count;

    const char* pref_label;
    struct wc_net_context* net_ctx;
    const struct Config* cfg;
    struct wc_net_info* ni;

    int* rir_cycle_exhausted;
};

int wc_lookup_exec_guard_no_next(struct wc_lookup_exec_guard_no_next_ctx* ctx);

struct wc_lookup_exec_guard_loop_ctx {
    struct wc_result* out;
    const char* current_host;
    const char* current_rir_guess;
    const char* start_host;
    const char* header_host;
    int header_is_iana;
    int auth;
    int apnic_erx_root;
    int query_is_cidr_effective;
    int seen_real_authoritative;
    int seen_apnic_iana_netblock;
    int seen_ripe_non_managed;
    int seen_afrinic_iana_blk;
    int seen_lacnic_unallocated;
    int seen_arin_no_match_cidr;

    char** visited;
    int visited_count;

    char* next_host;
    size_t next_host_len;

    int ref_explicit_allow_visited;
    int allow_apnic_ambiguous_revisit;
    int* apnic_revisit_used;
    int apnic_force_ip;
    int allow_cycle_on_loop;

    struct wc_net_info* ni;

    int* rir_cycle_exhausted;
};

int wc_lookup_exec_guard_loop(struct wc_lookup_exec_guard_loop_ctx* ctx);

#endif // WC_LOOKUP_EXEC_GUARD_H_
