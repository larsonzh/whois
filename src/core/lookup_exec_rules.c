// SPDX-License-Identifier: MIT
// lookup_exec_rules.c - Deterministic rule predicates for lookup execution

#include <strings.h>

#include "wc/wc_server.h"
#include "lookup_internal.h"
#include "lookup_exec_rules.h"

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
