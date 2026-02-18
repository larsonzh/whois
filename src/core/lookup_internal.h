// SPDX-License-Identifier: MIT
// lookup_internal.h - Internal helpers for lookup.c
#ifndef WC_LOOKUP_INTERNAL_H_
#define WC_LOOKUP_INTERNAL_H_

#include <stddef.h>

#include "wc/wc_config.h"
#include "wc/wc_dns.h"
#include "wc/wc_net.h"

const char* wc_lookup_find_case_insensitive(const char* haystack, const char* needle);
int wc_lookup_line_contains_case_insensitive(const char* line, size_t len, const char* needle);
int wc_lookup_line_starts_with_case_insensitive_n(const char* line, size_t len, const char* prefix);

int wc_lookup_body_contains_no_match(const char* body);
int wc_lookup_body_contains_invalid_search_key(const char* body);
int wc_lookup_body_has_strong_redirect_hint(const char* body);
int wc_lookup_body_has_non_authoritative_marker(const char* body);
int wc_lookup_body_is_semantically_empty(const char* body);
int wc_lookup_body_is_arin_banner_only(const char* body);
int wc_lookup_body_contains_apnic_iana_netblock(const char* body);
int wc_lookup_body_contains_apnic_iana_not_allocated_disclaimer(const char* body);
int wc_lookup_body_contains_ripe_non_managed(const char* body);
int wc_lookup_body_contains_lacnic_rate_limit(const char* body);
int wc_lookup_body_contains_rate_limit(const char* body);
int wc_lookup_body_contains_access_denied(const char* body);
int wc_lookup_body_contains_temporary_denied(const char* body);
int wc_lookup_body_contains_permanent_denied(const char* body);
int wc_lookup_body_contains_ripe_access_denied(const char* body);
char* wc_lookup_strip_access_denied_lines(const char* body);
char* wc_lookup_strip_rate_limit_lines(const char* body);
void wc_lookup_format_time(char* buf, size_t cap);
int wc_lookup_body_contains_apnic_erx_hint(const char* body);
int wc_lookup_body_contains_apnic_erx_hint_strict(const char* body);
int wc_lookup_body_contains_erx_legacy(const char* body);
int wc_lookup_body_contains_apnic_transfer_to_apnic(const char* body);
int wc_lookup_body_contains_erx_netname(const char* body);
int wc_lookup_body_contains_lacnic_unallocated(const char* body);
int wc_lookup_body_contains_erx_iana_marker(const char* body);
int wc_lookup_body_is_comment_only(const char* body);
const char* wc_lookup_detect_rir_header_host(const char* body);
int wc_lookup_body_contains_full_ipv4_space(const char* body);
int wc_lookup_body_contains_ipv6_root(const char* body);

const char* wc_lookup_known_ip_host_from_literal(const char* ip_literal);
void wc_lookup_normalize_host_token(const char* in, char* out, size_t out_len);
int wc_lookup_host_tokens_equal(const char* a, const char* b);
int wc_lookup_ip_matches_host(const char* ip_literal, const char* host);
int wc_lookup_referral_is_explicit(const char* body, const char* ref_host);
char* wc_lookup_extract_referral_fallback(const char* body);
int wc_lookup_visited_has(char** visited, int visited_count, const char* host);
void wc_lookup_visited_remove(char** visited, int* visited_count, const char* host);
int wc_lookup_parse_referral_target(const char* ref, char* host, size_t cap, int* out_port);
int wc_lookup_hosts_match(const char* a, const char* b);

int wc_lookup_header_matches_host(const char* line, const char* host);
int wc_lookup_is_hop_header_line(const char* line);
void wc_lookup_compact_hop_headers(char* combined);
int wc_lookup_extract_hop_host_from_line(const char* line, char* out, size_t out_len);
void wc_lookup_strip_bodies_after_authoritative_hop(char* combined,
                                                    const char* start_host,
                                                    const char* authoritative_host);
void wc_lookup_strip_bodies_before_authoritative_hop(char* combined,
                                                     const char* start_host,
                                                     const char* authoritative_host);
int wc_lookup_has_hop_header(const char* combined, const char* host);
char* wc_lookup_insert_header_before_authoritative(char* combined, const char* host);

int wc_lookup_query_has_arin_prefix(const char* query);
char* wc_lookup_extract_cidr_base(const char* query);
int wc_lookup_query_is_ipv4_literal(const char* query);
int wc_lookup_query_is_ip_literal(const char* query);
int wc_lookup_query_is_cidr(const char* query);
int wc_lookup_query_is_asn(const char* query);
int wc_lookup_query_is_arin_nethandle(const char* query);

int wc_lookup_erx_baseline_recheck_guard_get(void);
void wc_lookup_erx_baseline_recheck_guard_set(int value);
int wc_lookup_rir_cycle_next(const char* current_rir,
                             char** visited,
                             int visited_count,
                             char* out,
                             size_t outlen);

int wc_lookup_should_trace_dns(const wc_net_context_t* net_ctx, const Config* cfg);
int wc_lookup_family_to_af(unsigned char fam, const char* token);
int wc_lookup_effective_family(int family_hint, const char* token);
void wc_lookup_record_backoff_result(const Config* cfg,
                                     const char* token,
                                     int family_hint,
                                     int success);
void wc_lookup_compute_canonical_host(const char* current_host,
                                      const char* rir,
                                      char* out,
                                      size_t out_len);
void wc_lookup_log_candidates(int hop,
                              const char* server,
                              const char* rir,
                              const wc_dns_candidate_list_t* cands,
                              const char* canonical_host,
                              const char* pref_label,
                              const wc_net_context_t* net_ctx,
                              const Config* cfg);
void wc_lookup_log_fallback(int hop,
                            const char* cause,
                            const char* action,
                            const char* domain,
                            const char* target,
                            const char* status,
                            unsigned int flags,
                            int err_no,
                            int empty_retry_count,
                            const char* pref_label,
                            const wc_net_context_t* net_ctx,
                            const Config* cfg);
void wc_lookup_log_dns_error(const char* host,
                             const char* canonical_host,
                             int gai_error,
                             int negative_cache,
                             const wc_net_context_t* net_ctx,
                             const Config* cfg);
int wc_lookup_should_skip_fallback(const char* server,
                                   const char* candidate,
                                   int family,
                                   int allow_skip,
                                   const wc_net_context_t* net_ctx,
                                   const Config* cfg);
void wc_lookup_log_dns_health(const char* host,
                              int family,
                              const wc_net_context_t* net_ctx,
                              const Config* cfg);

#endif // WC_LOOKUP_INTERNAL_H_
