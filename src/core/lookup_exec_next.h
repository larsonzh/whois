// SPDX-License-Identifier: MIT
// lookup_exec_next.h - Next-hop selection for lookup exec
#ifndef WC_LOOKUP_EXEC_NEXT_H_
#define WC_LOOKUP_EXEC_NEXT_H_

#include <stddef.h>

struct Config;
struct wc_lookup_opts;
struct wc_net_context;
typedef struct wc_selftest_fault_profile_s wc_selftest_fault_profile_t;

struct wc_lookup_exec_next_ctx {
    const struct wc_lookup_opts* zopts;
    const struct Config* cfg;
    const struct wc_net_context* net_ctx;
    const wc_selftest_fault_profile_t* fault_profile;

    const char* current_host;
    const char* current_rir_guess;
    int current_port;
    const char* body;
    int hops;
    int auth;
    int need_redir_eval;
    int header_hint_valid;
    const char* header_hint_host;
    int allow_cycle_on_loop;
    int force_stop_authoritative;
    int force_rir_cycle;
    int apnic_erx_root;
    int apnic_redirect_reason;
    int apnic_erx_authoritative_stop;
    int apnic_erx_legacy;
    int erx_fast_authoritative;
    int apnic_erx_ripe_non_managed;

    const char* ref;
    const char* ref_host;
    int ref_port;
    int ref_explicit;
    const char* combined;

    unsigned int* fallback_flags;
    const char* pref_label;
    char** visited;
    int* visited_count;

    int* apnic_ambiguous_revisit_used;
    int* stop_with_apnic_authority;
    int* rir_cycle_exhausted;
    char* apnic_erx_ref_host;
    size_t apnic_erx_ref_host_len;

    char* next_host;
    size_t next_host_len;
    int* have_next;
    int* next_port;
    int* ref_explicit_allow_visited;
};

void wc_lookup_exec_pick_next_hop(struct wc_lookup_exec_next_ctx* ctx);

#endif // WC_LOOKUP_EXEC_NEXT_H_
