// SPDX-License-Identifier: MIT

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wc/wc_redirect.h"
#include "lookup_internal.h"

int wc_output_is_debug_enabled(void)
{
    return 0;
}

static char* build_response(size_t prefix_len, const char* suffix)
{
    size_t suffix_len = strlen(suffix);
    char* response = malloc(prefix_len + suffix_len + 1);
    if (!response) return NULL;
    memset(response, '#', prefix_len);
    memcpy(response + prefix_len, suffix, suffix_len + 1);
    return response;
}

static char* truncate_response(const char* response, size_t cap)
{
    char* truncated = malloc(cap + 1);
    if (!truncated) return NULL;
    memcpy(truncated, response, cap);
    truncated[cap] = '\0';
    return truncated;
}

static int audit_ipv4_authority_tail(size_t cap)
{
    char* full = build_response(cap, "\nNetRange: 192.0.2.0 - 192.0.2.255\n");
    char* truncated = full ? truncate_response(full, cap) : NULL;
    int full_auth = full ? is_authoritative_response(full) : -1;
    int truncated_auth = truncated ? is_authoritative_response(truncated) : -1;
    int pass = full_auth == 1 && truncated_auth == 0;
    printf("[RESPONSE-LIMIT-CLASSIFY] case=ipv4-authority-tail status=%s full_auth=%d truncated_auth=%d\n",
           pass ? "PASS" : "FAIL", full_auth, truncated_auth);
    free(truncated);
    free(full);
    return pass ? 0 : 1;
}

static int audit_ipv6_referral_tail(size_t cap)
{
    char* full = build_response(cap, "\nReferralServer: whois://whois.apnic.net\n");
    char* truncated = full ? truncate_response(full, cap) : NULL;
    char* full_ref = full ? extract_refer_server(full) : NULL;
    char* truncated_ref = truncated ? extract_refer_server(truncated) : NULL;
    int pass = full_ref && strcmp(full_ref, "whois.apnic.net") == 0 && !truncated_ref;
    printf("[RESPONSE-LIMIT-CLASSIFY] case=ipv6-referral-tail status=%s full_ref=%s truncated_ref=%s\n",
           pass ? "PASS" : "FAIL", full_ref ? full_ref : "none",
           truncated_ref ? truncated_ref : "none");
    free(truncated_ref);
    free(full_ref);
    free(truncated);
    free(full);
    return pass ? 0 : 1;
}

static int audit_cidr_erx_tail(size_t cap)
{
    char* full = build_response(cap, "\nNetName: ERX-NETBLOCK\n");
    char* truncated = full ? truncate_response(full, cap) : NULL;
    int full_erx = full ? wc_lookup_body_contains_erx_iana_marker(full) : -1;
    int truncated_erx = truncated ? wc_lookup_body_contains_erx_iana_marker(truncated) : -1;
    int pass = full_erx == 1 && truncated_erx == 0;
    printf("[RESPONSE-LIMIT-CLASSIFY] case=cidr-erx-tail status=%s full_erx=%d truncated_erx=%d\n",
           pass ? "PASS" : "FAIL", full_erx, truncated_erx);
    free(truncated);
    free(full);
    return pass ? 0 : 1;
}

static int audit_batch_denied_tail(size_t cap)
{
    char* full = build_response(cap, "\nNetRange: 198.51.100.0 - 198.51.100.255\nAccess denied\n");
    char* truncated = full ? truncate_response(full, cap) : NULL;
    int full_denied = full ? wc_lookup_body_contains_access_denied(full) : -1;
    int truncated_denied = truncated ? wc_lookup_body_contains_access_denied(truncated) : -1;
    int pass = full_denied == 1 && truncated_denied == 0;
    printf("[RESPONSE-LIMIT-CLASSIFY] case=batch-denied-tail status=%s full_denied=%d truncated_denied=%d\n",
           pass ? "PASS" : "FAIL", full_denied, truncated_denied);
    free(truncated);
    free(full);
    return pass ? 0 : 1;
}

int main(void)
{
    const size_t cap = 64;
    int failures = 0;
    failures += audit_ipv4_authority_tail(cap);
    failures += audit_ipv6_referral_tail(cap);
    failures += audit_cidr_erx_tail(cap);
    failures += audit_batch_denied_tail(cap);
    printf("[RESPONSE-LIMIT-CLASSIFY] summary status=%s cases=4 failures=%d classification_drift=%s\n",
           failures == 0 ? "PASS" : "FAIL", failures,
           failures == 0 ? "confirmed" : "unconfirmed");
    return failures == 0 ? 0 : 1;
}