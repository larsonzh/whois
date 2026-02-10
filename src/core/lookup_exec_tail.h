// SPDX-License-Identifier: MIT
// lookup_exec_tail.h - Authority and guard tail handling
#ifndef WC_LOOKUP_EXEC_TAIL_H_
#define WC_LOOKUP_EXEC_TAIL_H_

#include <stddef.h>

struct Config;
struct wc_lookup_opts;
struct wc_result;
struct wc_net_context;
struct wc_net_info;

struct wc_lookup_exec_tail_ctx {
    struct wc_result* out;
    const struct wc_lookup_opts* zopts;
    const struct Config* cfg;
    struct wc_net_context* net_ctx;
    struct wc_net_info* ni;

    const char* start_host;
    char* current_host;
    size_t current_host_len;
    int* current_port;
    int hops;

    const char* current_rir_guess;
    const char* header_host;
    int header_is_iana;

    int auth;
    int need_redir;

    int have_next;
    char* next_host;
    size_t next_host_len;
    int* next_port;

    char** ref;

    int* pending_referral;
    int* redirect_cap_hit;
    int* apnic_force_ip;
    int* apnic_revisit_used;
    int allow_apnic_ambiguous_revisit;
    int ref_explicit_allow_visited;
    int allow_cycle_on_loop;

    int apnic_erx_root;
    int apnic_erx_ripe_non_managed;
    int apnic_erx_legacy;
    int apnic_erx_stop;
    int apnic_erx_stop_unknown;
    const char* apnic_erx_root_host;
    const char* apnic_erx_root_ip;
    const char* apnic_erx_stop_host;
    const char* apnic_last_ip;

    int stop_with_header_authority;
    const char* header_authority_host;
    int stop_with_apnic_authority;

    int seen_real_authoritative;
    int seen_apnic_iana_netblock;
    int seen_ripe_non_managed;
    int seen_afrinic_iana_blk;
    int seen_lacnic_unallocated;
    int seen_arin_no_match_cidr;

    int query_is_cidr_effective;
    int query_is_cidr;
    int arin_retry_active;
    int* force_original_query;

    int erx_fast_authoritative;
    const char* erx_fast_authoritative_host;
    const char* erx_fast_authoritative_ip;

    int* last_hop_authoritative;
    int* last_hop_need_redirect;
    int* last_hop_has_ref;

    char** visited;
    int visited_count;
    const char* pref_label;
    int* rir_cycle_exhausted;

    char** combined;
    int* additional_emitted;
    int emit_redirect_headers;
};

int wc_lookup_exec_handle_tail(struct wc_lookup_exec_tail_ctx* ctx);

#endif // WC_LOOKUP_EXEC_TAIL_H_
