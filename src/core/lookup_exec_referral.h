// SPDX-License-Identifier: MIT
// lookup_exec_referral.h - Referral parsing for lookup exec
#ifndef WC_LOOKUP_EXEC_REFERRAL_H_
#define WC_LOOKUP_EXEC_REFERRAL_H_

#include <stddef.h>

struct wc_lookup_exec_referral_ctx {
    const char* current_host;
    const char* current_rir_guess;
    const char* body;
    int ripe_non_managed;

    int apnic_erx_root;
    int apnic_redirect_reason;
    int apnic_erx_legacy;
    int apnic_erx_ripe_non_managed;
    int apnic_erx_arin_before_apnic;

    char** visited;
    int* visited_count;

    char** ref;
    char* ref_host;
    size_t ref_host_len;

    int* ref_explicit;
    int* apnic_erx_keep_ref;

    char* apnic_erx_ref_host;
    size_t apnic_erx_ref_host_len;
    int* apnic_erx_stop;
    char* apnic_erx_stop_host;
    size_t apnic_erx_stop_host_len;
    int* apnic_erx_seen_arin;
    char* apnic_erx_target_rir;
    size_t apnic_erx_target_rir_len;
};

void wc_lookup_exec_referral_parse(struct wc_lookup_exec_referral_ctx* ctx);

#endif // WC_LOOKUP_EXEC_REFERRAL_H_
