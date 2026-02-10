// SPDX-License-Identifier: MIT
// lookup_exec_decision.h - Redirect and next-hop decision helpers
#ifndef WC_LOOKUP_EXEC_DECISION_H_
#define WC_LOOKUP_EXEC_DECISION_H_

#include <stddef.h>

struct Config;
struct wc_lookup_opts;
struct wc_net_context;
struct wc_net_info;
typedef struct wc_selftest_fault_profile_s wc_selftest_fault_profile_t;

struct wc_lookup_exec_decision_ctx {
    const struct wc_lookup_opts* zopts;
    const struct Config* cfg;
    struct wc_net_context* net_ctx;
    const wc_selftest_fault_profile_t* fault_profile;
    struct wc_net_info* ni;
    const char* current_host;
    int current_port;
    int hops;
    int query_is_cidr;
    int query_is_cidr_effective;
    const char* cidr_base_query;

    char** body;
    int* auth;
    int* need_redir_eval;
    const char** current_rir_guess;
    const char** header_host;
    int* header_is_iana;
    int* allow_cycle_on_loop;
    int* need_redir;
    int* force_stop_authoritative;
    int* apnic_erx_suppress_current;

    char** ref;
    int* ref_port;
    int* ref_explicit;
    char* ref_host;
    size_t ref_host_len;

    char* header_authority_host;
    size_t header_authority_host_len;
    int* stop_with_header_authority;
    int* force_rir_cycle;
    int* apnic_erx_root;
    int* apnic_redirect_reason;
    int* apnic_erx_ripe_non_managed;
    int* apnic_erx_arin_before_apnic;
    int* apnic_erx_stop;
    char* apnic_erx_stop_host;
    size_t apnic_erx_stop_host_len;
    int* apnic_erx_seen_arin;
    char* apnic_erx_target_rir;
    size_t apnic_erx_target_rir_len;
    char* apnic_erx_ref_host;
    size_t apnic_erx_ref_host_len;
    int* apnic_erx_keep_ref;
    int* apnic_iana_netblock_cidr;
    int* apnic_erx_legacy;
    char* apnic_last_ip;
    size_t apnic_last_ip_len;
    int* apnic_ambiguous_revisit_used;
    int* stop_with_apnic_authority;
    int* rir_cycle_exhausted;
    int* apnic_erx_authoritative_stop;
    int* apnic_erx_stop_unknown;
    char* apnic_erx_root_host;
    size_t apnic_erx_root_host_len;
    char* apnic_erx_root_ip;
    size_t apnic_erx_root_ip_len;

    int* erx_marker_seen;
    char* erx_marker_host;
    size_t erx_marker_host_len;
    char* erx_marker_ip;
    size_t erx_marker_ip_len;
    int* erx_baseline_recheck_attempted;
    int* erx_fast_recheck_done;
    int* erx_fast_authoritative;
    char* erx_fast_authoritative_host;
    size_t erx_fast_authoritative_host_len;
    char* erx_fast_authoritative_ip;
    size_t erx_fast_authoritative_ip_len;

    int* last_hop_authoritative;
    int* last_hop_need_redirect;
    int* last_hop_has_ref;
    int* saw_rate_limit_or_denied;
    char* last_failure_host;
    size_t last_failure_host_len;
    char* last_failure_ip;
    size_t last_failure_ip_len;
    char* last_failure_rir;
    size_t last_failure_rir_len;
    const char** last_failure_status;
    const char** last_failure_desc;

    int* seen_real_authoritative;
    int* seen_apnic_iana_netblock;
    int* seen_ripe_non_managed;
    int* seen_afrinic_iana_blk;
    int* seen_arin_no_match_cidr;
    int* seen_lacnic_unallocated;

    char* header_hint_host;
    size_t header_hint_host_len;
    int* header_hint_valid;

    char* next_host;
    size_t next_host_len;
    int* have_next;
    int* next_port;
    int* ref_explicit_allow_visited;

    char** visited;
    int* visited_count;
    char* pref_label;
    char* combined;
    unsigned int* fallback_flags;

    int persistent_empty;
};

void wc_lookup_exec_decide_next(struct wc_lookup_exec_decision_ctx* ctx);

#endif // WC_LOOKUP_EXEC_DECISION_H_
