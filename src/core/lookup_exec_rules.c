// SPDX-License-Identifier: MIT
// lookup_exec_rules.c - Deterministic rule predicates for lookup execution

#include <strings.h>

#include "wc/wc_dns.h"
#include "wc/wc_known_ips.h"
#include "wc/wc_server.h"
#include "lookup_internal.h"
#include "lookup_exec_rules.h"

int wc_lookup_exec_rule_is_empty_or_banner_only(
    int auth,
    const char* body)
{
    if (!body || !body[0]) return 1;
    if (auth) return 0;

    return wc_lookup_body_is_comment_only(body) ? 1 : 0;
}

const char* wc_lookup_exec_rule_effective_rir(
    const char* current_rir_guess,
    const char* current_host)
{
    if (current_rir_guess && current_rir_guess[0] &&
        strcasecmp(current_rir_guess, "unknown") != 0) {
        return current_rir_guess;
    }

    if (!current_host || !current_host[0]) {
        return current_rir_guess;
    }

    {
        const char* host_for_guess = current_host;
        if (wc_dns_is_ip_literal(host_for_guess)) {
            const char* mapped = wc_lookup_known_ip_host_from_literal(host_for_guess);
            if (mapped && mapped[0]) {
                host_for_guess = mapped;
            }
        }

        {
            const char* canon = wc_dns_canonical_alias(host_for_guess);
            if (canon && canon[0]) {
                host_for_guess = canon;
            }
        }

        {
            const char* guessed = wc_guess_rir(host_for_guess);
            if (guessed && guessed[0] && strcasecmp(guessed, "unknown") != 0) {
                return guessed;
            }
        }
    }

    return current_rir_guess;
}

int wc_lookup_exec_rule_is_arin_no_match_marker(const char* body)
{
    return wc_lookup_body_contains_no_match(body) ? 1 : 0;
}

int wc_lookup_exec_rule_is_ripe_non_managed_marker(const char* body)
{
    return wc_lookup_body_contains_ripe_non_managed(body) ? 1 : 0;
}

int wc_lookup_exec_rule_is_afrinic_full_space_marker(const char* body)
{
    return wc_lookup_body_contains_full_ipv4_space(body) ? 1 : 0;
}

int wc_lookup_exec_rule_is_lacnic_ambiguous_marker(const char* body)
{
    return wc_lookup_find_case_insensitive(body, "query terms are ambiguous") ? 1 : 0;
}

int wc_lookup_exec_rule_is_lacnic_unallocated_marker(const char* body)
{
    return wc_lookup_body_contains_lacnic_unallocated(body) ? 1 : 0;
}

int wc_lookup_exec_rule_marker_action_for_cidr(
    int query_is_cidr,
    int marker_hit,
    int cidr_erx_recheck_enabled)
{
    if (!query_is_cidr || !marker_hit) {
        return WC_LOOKUP_MARKER_ACTION_NONE;
    }

    return cidr_erx_recheck_enabled
        ? WC_LOOKUP_MARKER_ACTION_RECHECK
        : WC_LOOKUP_MARKER_ACTION_REDIRECT;
}

int wc_lookup_exec_rule_allow_apnic_hint_strict(const char* body)
{
    if (!body) return 0;

    if (wc_lookup_body_contains_erx_iana_marker(body)) {
        return 0;
    }

    return (wc_lookup_body_contains_apnic_erx_hint(body) &&
            wc_lookup_body_contains_apnic_erx_hint_strict(body)) ? 1 : 0;
}

int wc_lookup_exec_rule_should_promote_fast_authoritative(
    int recheck_authority_known,
    int recheck_non_auth,
    const char* recheck_authoritative_host)
{
    if (!(recheck_authority_known && !recheck_non_auth) ||
        !recheck_authoritative_host || !recheck_authoritative_host[0]) {
        return 0;
    }

    {
        const char* auth_rir = wc_guess_rir(recheck_authoritative_host);
        return (auth_rir && strcasecmp(auth_rir, "apnic") == 0) ? 1 : 0;
    }
}

int wc_lookup_exec_rule_should_short_circuit_first_hop_apnic(
    int hops,
    int fast_authoritative,
    int auth,
    int need_redir_eval,
    const char* ref,
    const char* current_rir_guess)
{
    int has_ref = (ref && ref[0]) ? 1 : 0;

    return (hops == 0 && fast_authoritative && auth && !need_redir_eval &&
            !has_ref && current_rir_guess &&
            strcasecmp(current_rir_guess, "apnic") == 0) ? 1 : 0;
}

int wc_lookup_exec_rule_is_weak_non_authoritative_signal(const char* body)
{
    if (!body || !body[0]) {
        return 0;
    }

    if (wc_lookup_find_case_insensitive(body, "not allocated to apnic")) {
        return 1;
    }
    if (wc_lookup_find_case_insensitive(body, "not fully allocated to apnic")) {
        return 1;
    }
    if (wc_lookup_find_case_insensitive(body, "not administered by apnic")) {
        return 1;
    }
    if (wc_lookup_find_case_insensitive(body, "non-ripe-ncc-managed-address-block")) {
        return 1;
    }

    return 0;
}

int wc_lookup_exec_rule_referral_confidence(
    const char* current_rir_guess,
    const char* body,
    const char* ref_host,
    int ref_explicit,
    int need_redir_eval)
{
    if (!ref_host || !ref_host[0]) {
        return WC_LOOKUP_REFERRAL_CONFIDENCE_BLOCK;
    }

    if (ref_explicit) {
        return WC_LOOKUP_REFERRAL_CONFIDENCE_HIGH;
    }

    if (need_redir_eval || wc_lookup_exec_rule_is_weak_non_authoritative_signal(body)) {
        return WC_LOOKUP_REFERRAL_CONFIDENCE_LOW;
    }

    if (current_rir_guess && strcasecmp(current_rir_guess, "arin") == 0 &&
        wc_lookup_exec_rule_is_arin_no_match_marker(body)) {
        return WC_LOOKUP_REFERRAL_CONFIDENCE_LOW;
    }

    return WC_LOOKUP_REFERRAL_CONFIDENCE_HIGH;
}
