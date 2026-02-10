// SPDX-License-Identifier: MIT
// lookup_exec_authority.h - Authority tail handling for lookup exec
#ifndef WC_LOOKUP_EXEC_AUTHORITY_H_
#define WC_LOOKUP_EXEC_AUTHORITY_H_

struct wc_lookup_opts;
struct wc_result;
struct wc_net_info;

struct wc_lookup_exec_authority_ctx {
    struct wc_result* out;
    const struct wc_lookup_opts* zopts;
    const struct wc_net_info* ni;

    const char* current_host;
    const char* current_rir_guess;
    const char* header_authority_host;
    const char* header_host;

    int header_is_iana;
    int stop_with_header_authority;
    int stop_with_apnic_authority;
    int apnic_erx_stop;
    int apnic_erx_stop_unknown;
    const char* apnic_erx_root_host;
    const char* apnic_erx_root_ip;
    const char* apnic_erx_stop_host;
    const char* apnic_last_ip;

    int apnic_erx_root;
    int apnic_erx_ripe_non_managed;
    int apnic_erx_legacy;

    int seen_real_authoritative;
    int seen_apnic_iana_netblock;
    int seen_ripe_non_managed;
    int seen_afrinic_iana_blk;
    int seen_lacnic_unallocated;
    int seen_arin_no_match_cidr;
    int query_is_cidr_effective;

    int auth;
    int need_redir;
    int have_next;

    int erx_fast_authoritative;
    const char* erx_fast_authoritative_host;
    const char* erx_fast_authoritative_ip;

    int* redirect_cap_hit;
    char** ref;
};

int wc_lookup_exec_check_authority(struct wc_lookup_exec_authority_ctx* ctx);

#endif // WC_LOOKUP_EXEC_AUTHORITY_H_
