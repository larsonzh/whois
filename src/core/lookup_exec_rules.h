// SPDX-License-Identifier: MIT
// lookup_exec_rules.h - Deterministic rule predicates for lookup execution
#ifndef WC_LOOKUP_EXEC_RULES_H_
#define WC_LOOKUP_EXEC_RULES_H_

enum wc_lookup_exec_marker_action {
    WC_LOOKUP_MARKER_ACTION_NONE = 0,
    WC_LOOKUP_MARKER_ACTION_RECHECK = 1,
    WC_LOOKUP_MARKER_ACTION_REDIRECT = 2,
};

enum wc_lookup_exec_evidence_strength {
    WC_LOOKUP_EVIDENCE_NONE = 0,
    WC_LOOKUP_EVIDENCE_WEAK = 1,
    WC_LOOKUP_EVIDENCE_STRONG = 2,
};

enum wc_lookup_exec_referral_confidence {
    WC_LOOKUP_REFERRAL_CONFIDENCE_BLOCK = 0,
    WC_LOOKUP_REFERRAL_CONFIDENCE_LOW = 1,
    WC_LOOKUP_REFERRAL_CONFIDENCE_HIGH = 2,
};

int wc_lookup_exec_rule_is_empty_or_banner_only(
    int auth,
    const char* body);

const char* wc_lookup_exec_rule_effective_rir(
    const char* current_rir_guess,
    const char* current_host);

int wc_lookup_exec_rule_is_arin_no_match_marker(const char* body);
int wc_lookup_exec_rule_is_ripe_non_managed_marker(const char* body);
int wc_lookup_exec_rule_is_afrinic_full_space_marker(const char* body);
int wc_lookup_exec_rule_is_lacnic_ambiguous_marker(const char* body);
int wc_lookup_exec_rule_is_lacnic_unallocated_marker(const char* body);

int wc_lookup_exec_rule_marker_action_for_cidr(
    int query_is_cidr,
    int marker_hit,
    int cidr_erx_recheck_enabled);

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

int wc_lookup_exec_rule_is_weak_non_authoritative_signal(const char* body);

int wc_lookup_exec_rule_referral_confidence(
    const char* current_rir_guess,
    const char* body,
    const char* ref_host,
    int ref_explicit,
    int need_redir_eval);

#endif // WC_LOOKUP_EXEC_RULES_H_
