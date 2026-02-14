// SPDX-License-Identifier: MIT
// lookup_exec_rules.h - Deterministic rule predicates for lookup execution
#ifndef WC_LOOKUP_EXEC_RULES_H_
#define WC_LOOKUP_EXEC_RULES_H_

int wc_lookup_exec_rule_allow_apnic_hint_strict(const char* body);

int wc_lookup_exec_rule_should_promote_fast_authoritative(
    int recheck_authority_known,
    int recheck_non_auth,
    const char* recheck_authoritative_host);

int wc_lookup_exec_rule_should_short_circuit_first_hop_apnic(
    int hops,
    int fast_authoritative,
    int auth,
    int need_redir_eval,
    const char* ref,
    const char* current_rir_guess);

#endif // WC_LOOKUP_EXEC_RULES_H_
