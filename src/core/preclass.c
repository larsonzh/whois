#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32) && !defined(__MINGW32__)
#include <strings.h>
#endif

#if defined(_WIN32) || defined(__MINGW32__)
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include "wc/wc_preclass.h"
#include "wc/wc_preclass_table.h"
#include "wc/wc_client_util.h"
#include "wc/wc_server.h"

int wc_preclass_csv_is_default_marker(const char* csv)
{
	const char* p;
	int saw_token = 0;

	if (!csv)
		return 0;

	p = csv;
	while (*p) {
		const char* start;
		const char* end;
		size_t tlen;

		while (*p == ',' || isspace((unsigned char)*p))
			++p;
		if (!*p)
			break;

		start = p;
		while (*p && *p != ',')
			++p;
		end = p;

		while (end > start && isspace((unsigned char)end[-1]))
			--end;
		tlen = (size_t)(end - start);
		if (tlen == 0)
			continue;

		if (saw_token)
			return 0;
		if (tlen != 7 || strncasecmp(start, "default", 7) != 0)
			return 0;
		saw_token = 1;
	}

	return saw_token;
}

static const char* wc_preclass_reason_non_ip_input_literal(void)
{
	return "NON_IP_INPUT";
}

static const char* wc_preclass_confidence_code_c0_literal(void)
{
	return "C0";
}

static const char* wc_preclass_confidence_code_c1_literal(void)
{
	return "C1";
}

static const char* wc_preclass_confidence_code_c2_literal(void)
{
	return "C2";
}

static const char* wc_preclass_confidence_code_c3_literal(void)
{
	return "C3";
}

static const char* wc_preclass_observe_reason_prefix_literal(void)
{
	return "PRECLASS_REASON_";
}

static const char* wc_preclass_observe_reason_code(const char* reason)
{
	if (!reason || !*reason)
		return wc_preclass_reason_non_ip_input_literal();
	return reason;
}

static int wc_preclass_reason_has_observe_prefix(const char* reason, const char* prefix, size_t prefix_len)
{
	return reason && *reason &&
		prefix && *prefix &&
		strncmp(reason, prefix, prefix_len) == 0 &&
		reason[prefix_len] != '\0';
}

static const char* wc_preclass_observe_reason_key(const char* reason)
{
	const char* prefix = wc_preclass_observe_reason_prefix_literal();
	const size_t prefix_len = strlen(prefix);
	if (!reason || !*reason)
		return wc_preclass_reason_non_ip_input_literal();
	if (wc_preclass_reason_has_observe_prefix(reason, prefix, prefix_len))
		return reason + prefix_len;
	return reason;
}

static int wc_preclass_confidence_token_matches(const char* confidence, const char* token)
{
	return confidence && *confidence && token && strcmp(confidence, token) == 0;
}

static int wc_preclass_confidence_token_level(const char* confidence)
{
	if (!confidence || !*confidence)
		return 0;
	if (wc_preclass_confidence_token_matches(confidence, "high"))
		return 3;
	if (wc_preclass_confidence_token_matches(confidence, "medium"))
		return 2;
	if (wc_preclass_confidence_token_matches(confidence, "low"))
		return 1;
	return 0;
}

static int wc_preclass_confidence_rank_from_level(int level)
{
	if (level >= 3)
		return 3;
	if (level == 2)
		return 2;
	if (level == 1)
		return 1;
	return 0;
}

static const char* wc_preclass_observe_confidence_code(const char* confidence)
{
	int level = wc_preclass_confidence_rank_from_level(
		wc_preclass_confidence_token_level(confidence));
	if (level >= 3)
		return wc_preclass_confidence_code_c3_literal();
	if (level == 2)
		return wc_preclass_confidence_code_c2_literal();
	if (level == 1)
		return wc_preclass_confidence_code_c1_literal();
	return wc_preclass_confidence_code_c0_literal();
}

static int wc_preclass_observe_confidence_rank(const char* confidence)
{
	return wc_preclass_confidence_token_level(confidence);
}

void wc_preclass_observation_codes(const char* reason,
		const char* confidence,
		const char** reason_code,
		const char** reason_key,
		const char** confidence_code,
		int* confidence_rank)
{
	if (reason_code)
		*reason_code = wc_preclass_observe_reason_code(reason);
	if (reason_key)
		*reason_key = wc_preclass_observe_reason_key(reason);
	if (confidence_code)
		*confidence_code = wc_preclass_observe_confidence_code(confidence);
	if (confidence_rank)
		*confidence_rank = wc_preclass_observe_confidence_rank(confidence);
}

static int wc_preclass_parse_cidr_query(const char* query,
		char* base,
		size_t base_len,
		int* out_prefix)
{
	if (!query || !base || base_len == 0 || !out_prefix)
		return 0;
	const char* start = query;
	while (*start && isspace((unsigned char)*start))
		++start;
	const char* slash = strchr(start, '/');
	if (!slash)
		return 0;
	const char* end = slash;
	while (end > start && isspace((unsigned char)end[-1]))
		--end;
	if (end <= start)
		return 0;
	size_t len = (size_t)(end - start);
	if (len >= base_len)
		len = base_len - 1;
	memcpy(base, start, len);
	base[len] = '\0';
	const char* pref = slash + 1;
	while (*pref && isspace((unsigned char)*pref))
		++pref;
	if (!*pref)
		return 0;
	char* endp = NULL;
	long v = strtol(pref, &endp, 10);
	if (endp == pref)
		return 0;
	while (endp && *endp) {
		if (!isspace((unsigned char)*endp))
			return 0;
		++endp;
	}
	*out_prefix = (int)v;
	return 1;
}

static const char* wc_preclass_non_ip_literal(void)
{
	return "non-ip";
}

static const char* wc_preclass_match_layer_cidr_compare_literal(void)
{
	return "cidr";
}

static const char* wc_preclass_match_layer_ip_compare_literal(void)
{
	return "ip";
}

static int wc_preclass_has_text_value(const char* value)
{
	return (value && *value) ? 1 : 0;
}

static int wc_preclass_token_equals(const char* lhs, const char* rhs)
{
	return wc_preclass_has_text_value(lhs) && rhs && strcmp(lhs, rhs) == 0;
}

static int wc_preclass_match_layer_is_cidr_literal(const char* match_layer)
{
	return wc_preclass_token_equals(match_layer, wc_preclass_match_layer_cidr_compare_literal());
}

static int wc_preclass_match_layer_is_ip_literal(const char* match_layer)
{
	return wc_preclass_token_equals(match_layer, wc_preclass_match_layer_ip_compare_literal());
}

static const char* wc_preclass_match_layer_non_ip_label_literal(void)
{
	return wc_preclass_non_ip_literal();
}

static const char* wc_preclass_action_source_decision_value_literal(void)
{
	return "decision";
}

static const char* wc_preclass_input_label_unknown_literal(void)
{
	return wc_preclass_match_layer_non_ip_label_literal();
}

static const char* wc_preclass_match_layer_output_label(const char* match_layer)
{
	if (wc_preclass_match_layer_is_cidr_literal(match_layer))
		return wc_preclass_match_layer_cidr_compare_literal();
	if (wc_preclass_match_layer_is_ip_literal(match_layer))
		return wc_preclass_match_layer_ip_compare_literal();
	return NULL;
}

static const char* wc_preclass_input_label_from_match_layer(const char* match_layer)
{
	const char* label = wc_preclass_match_layer_output_label(match_layer);
	if (label && *label)
		return label;
	return wc_preclass_input_label_unknown_literal();
}

static int wc_preclass_has_decision_action(const char* decision_action)
{
	return wc_preclass_has_text_value(decision_action);
}

static const char* wc_preclass_action_hint_applied_literal(void)
{
	return "hint-applied";
}

static const char* wc_preclass_action_preclass_short_circuit_literal(void)
{
	return "preclass-short-circuit-unknown";
}

static const char* wc_preclass_action_step47_short_circuit_literal(void)
{
	return "step47-short-circuit-unknown";
}

static const char* wc_preclass_route_change_normalized_literal(void)
{
	return "route-change-normalized";
}

static int wc_preclass_action_allows_route_change(const char* action)
{
	if (!wc_preclass_has_text_value(action))
		return 0;
	if (wc_preclass_token_equals(action, wc_preclass_action_hint_applied_literal()))
		return 1;
	if (wc_preclass_token_equals(action, wc_preclass_action_preclass_short_circuit_literal()))
		return 1;
	if (wc_preclass_token_equals(action, wc_preclass_action_step47_short_circuit_literal()))
		return 1;
	return 0;
}

static const char* wc_preclass_action_source_default_literal(void)
{
	return "default";
}

static const char* wc_preclass_fallback_none_value_literal(void)
{
	return "none";
}

static const char* wc_preclass_normalize_action_source(const char* action_source)
{
	if (!wc_preclass_has_text_value(action_source))
		return wc_preclass_action_source_default_literal();
	return action_source;
}

static const char* wc_preclass_normalize_fallback_reason(const char* fallback_reason)
{
	if (!wc_preclass_has_text_value(fallback_reason))
		return wc_preclass_fallback_none_value_literal();
	return fallback_reason;
}

static int wc_preclass_route_change_enabled_flag(void)
{
	return 1;
}

static int wc_preclass_route_change_disabled_flag(void)
{
	return 0;
}

static int wc_preclass_normalize_route_change_flag(int route_change)
{
	return route_change != 0 ? wc_preclass_route_change_enabled_flag() : wc_preclass_route_change_disabled_flag();
}

static const char* wc_preclass_observe_only_action_literal(void)
{
	return "observe-only";
}

static const char* wc_preclass_hint_disabled_action_value_literal(void)
{
	return "hint-disabled";
}

static int wc_preclass_decision_action_missing(const char* decision_action)
{
	return !wc_preclass_has_text_value(decision_action);
}

static const char* wc_preclass_normalize_decision_action(const char* decision_action)
{
	if (wc_preclass_decision_action_missing(decision_action))
		return wc_preclass_observe_only_action_literal();
	return decision_action;
}

static const char* wc_preclass_policy_action_source_literal(void)
{
	return "policy";
}

static const char* wc_preclass_decision_action_source_literal(void)
{
	return wc_preclass_action_source_decision_value_literal();
}

static const char* wc_preclass_disabled_fallback_reason_literal(void)
{
	return "preclass-disabled";
}

static const char* wc_preclass_policy_action_source(void)
{
	return wc_preclass_policy_action_source_literal();
}

static const char* wc_preclass_fallback_none_literal(void)
{
	return wc_preclass_fallback_none_value_literal();
}

static const char* wc_preclass_decision_none_literal(void)
{
	return "none";
}

static const char* wc_preclass_route_change_fallback(const char* fallback_reason)
{
	if (fallback_reason && strcmp(fallback_reason, wc_preclass_fallback_none_literal()) == 0)
		return wc_preclass_route_change_normalized_literal();
	return fallback_reason;
}

static const char* wc_preclass_default_action_literal(void)
{
	return wc_preclass_observe_only_action_literal();
}

static const char* wc_preclass_default_action_source_literal(void)
{
	return wc_preclass_action_source_default_literal();
}

static const char* wc_preclass_default_fallback_reason_literal(void)
{
	return "no-decision-action";
}

static const char* wc_preclass_default_action(void)
{
	return wc_preclass_default_action_literal();
}

static const char* wc_preclass_default_fallback_reason(void)
{
	return wc_preclass_default_fallback_reason_literal();
}

static const char* wc_preclass_default_non_ip_label(void)
{
	return wc_preclass_match_layer_non_ip_label_literal();
}

static const char* wc_preclass_default_input_label(void)
{
	return wc_preclass_default_non_ip_label();
}

static const char* wc_preclass_default_match_layer_non_ip(void)
{
	return wc_preclass_match_layer_non_ip_label_literal();
}

static const char* wc_preclass_default_match_layer(void)
{
	return wc_preclass_default_match_layer_non_ip();
}

static const char* wc_preclass_default_action_source(void)
{
	return wc_preclass_normalize_action_source(wc_preclass_default_action_source_literal());
}

static int wc_preclass_default_route_change(void)
{
	return wc_preclass_route_change_disabled_flag();
}

static const char* wc_preclass_decision_action_source(void)
{
	return wc_preclass_decision_action_source_literal();
}

static const char* wc_preclass_disabled_fallback_reason(void)
{
	return wc_preclass_disabled_fallback_reason_literal();
}

static const char* wc_preclass_decision_none_fallback_reason(void)
{
	return wc_preclass_normalize_fallback_reason(wc_preclass_decision_none_literal());
}

static const char* wc_preclass_match_layer_cidr_output_literal(void)
{
	return "cidr";
}

static const char* wc_preclass_match_layer_ip_output_literal(void)
{
	return "ip";
}

static const char* wc_preclass_match_layer_cidr_literal(void);
static const char* wc_preclass_match_layer_ip_literal(void);

static int wc_preclass_match_layer_from_query_kind_normalized(int query_is_cidr)
{
	return query_is_cidr ? 1 : 0;
}

static const char* wc_preclass_match_layer_from_query_kind(int query_is_cidr)
{
	if (wc_preclass_match_layer_from_query_kind_normalized(query_is_cidr))
		return wc_preclass_match_layer_cidr_literal();
	return wc_preclass_match_layer_ip_literal();
}

static const char* wc_preclass_match_layer_cidr_literal(void)
{
	return wc_preclass_match_layer_cidr_output_literal();
}

static const char* wc_preclass_match_layer_ip_literal(void)
{
	return wc_preclass_match_layer_ip_output_literal();
}

static int wc_preclass_disabled_route_change_reset(void)
{
	return wc_preclass_route_change_disabled_flag();
}

static const char* wc_preclass_hint_disabled_action_literal(void)
{
	return wc_preclass_hint_disabled_action_value_literal();
}

static const char* wc_preclass_hint_disabled_action_source(void)
{
	return wc_preclass_policy_action_source();
}

static int wc_preclass_route_change_block_reset(void)
{
	return wc_preclass_route_change_disabled_flag();
}

static const char* wc_preclass_route_change_fallback_apply(const char* fallback_reason)
{
	return wc_preclass_route_change_fallback(fallback_reason);
}

static int wc_preclass_apply_route_change_value(int route_change)
{
	return wc_preclass_normalize_route_change_flag(route_change);
}

static void wc_preclass_apply_disabled_decision_fields(wc_preclass_decision_fields_t* out_fields)
{
	out_fields->action = wc_preclass_hint_disabled_action_literal();
	out_fields->action_source = wc_preclass_hint_disabled_action_source();
	out_fields->fallback_reason = wc_preclass_disabled_fallback_reason();
	out_fields->route_change = wc_preclass_disabled_route_change_reset();
}

static const char* wc_preclass_apply_decision_none_fallback(void)
{
	return wc_preclass_decision_none_fallback_reason();
}

static void wc_preclass_apply_decision_action_fields(const char* decision_action,
		wc_preclass_decision_fields_t* out_fields)
{
	out_fields->action = wc_preclass_normalize_decision_action(decision_action);
	out_fields->action_source = wc_preclass_decision_action_source();
	out_fields->fallback_reason = wc_preclass_apply_decision_none_fallback();
}

static int wc_preclass_route_change_enabled_for_decision(const wc_preclass_decision_fields_t* out_fields)
{
	if (!out_fields)
		return 0;
	return out_fields->route_change == wc_preclass_route_change_enabled_flag();
}

static int wc_preclass_route_change_should_be_blocked(const wc_preclass_decision_fields_t* out_fields)
{
	return wc_preclass_route_change_enabled_for_decision(out_fields) &&
		!wc_preclass_action_allows_route_change(out_fields->action);
}

static void wc_preclass_apply_route_change_block(wc_preclass_decision_fields_t* out_fields)
{
	out_fields->route_change = wc_preclass_route_change_block_reset();
	out_fields->fallback_reason = wc_preclass_route_change_fallback_apply(out_fields->fallback_reason);
}

static int wc_preclass_route_change_block_required(wc_preclass_decision_fields_t* out_fields)
{
	return wc_preclass_route_change_should_be_blocked(out_fields);
}

static void wc_preclass_apply_route_change_policy(wc_preclass_decision_fields_t* out_fields)
{
	if (wc_preclass_route_change_block_required(out_fields))
		wc_preclass_apply_route_change_block(out_fields);
}

static void wc_preclass_set_decision_defaults(wc_preclass_decision_fields_t* out_fields)
{
	out_fields->action = wc_preclass_default_action();
	out_fields->action_source = wc_preclass_default_action_source();
	out_fields->match_layer = wc_preclass_default_match_layer();
	out_fields->fallback_reason = wc_preclass_default_fallback_reason();
	out_fields->input_label = wc_preclass_default_input_label();
	out_fields->route_change = wc_preclass_default_route_change();
}

static const char* wc_preclass_normalized_query_for_match(int query_is_cidr, const char* cidr_base, const char* query)
{
	return query_is_cidr ? cidr_base : query;
}

static int wc_preclass_should_apply_decision_action(const char* decision_action)
{
	return wc_preclass_has_decision_action(decision_action);
}

static void wc_preclass_apply_route_change_finalize(int route_change, wc_preclass_decision_fields_t* out_fields)
{
	out_fields->route_change = wc_preclass_apply_route_change_value(route_change);
	wc_preclass_apply_route_change_policy(out_fields);
}

static int wc_preclass_query_missing(const char* query)
{
	return !query || !*query;
}

static int wc_preclass_preclass_disabled_enabled(int preclass_disabled)
{
	return preclass_disabled != 0;
}

static int wc_preclass_decision_fields_missing(wc_preclass_decision_fields_t* out_fields)
{
	return !out_fields;
}

static const char* wc_preclass_match_layer_for_query_kind(int query_is_cidr)
{
	return wc_preclass_match_layer_from_query_kind(query_is_cidr);
}

void wc_preclass_resolve_decision_fields(const char* query,
		const char* decision_action,
		int route_change,
		int preclass_disabled,
		wc_preclass_decision_fields_t* out_fields)
{
	if (!out_fields)
		return;

	if (wc_preclass_decision_fields_missing(out_fields))
		return;

	wc_preclass_set_decision_defaults(out_fields);

	if (wc_preclass_query_missing(query)) {
		if (preclass_disabled)
			wc_preclass_apply_disabled_decision_fields(out_fields);
		return;
	}

	char cidr_base[256];
	int cidr_prefix = -1;
	int query_is_cidr = wc_preclass_parse_cidr_query(query,
		cidr_base,
		sizeof(cidr_base),
		&cidr_prefix);
	const char* normalized = wc_preclass_normalized_query_for_match(query_is_cidr, cidr_base, query);
	if (normalized && wc_client_is_valid_ip_address(normalized))
		out_fields->match_layer = wc_preclass_match_layer_for_query_kind(query_is_cidr);

	out_fields->input_label = wc_preclass_input_label_from_match_layer(out_fields->match_layer);

	if (wc_preclass_preclass_disabled_enabled(preclass_disabled)) {
		wc_preclass_apply_disabled_decision_fields(out_fields);
		return;
	}

	if (wc_preclass_should_apply_decision_action(decision_action)) {
		wc_preclass_apply_decision_action_fields(decision_action, out_fields);
	}

	wc_preclass_apply_route_change_finalize(route_change, out_fields);
}

static const char* wc_preclass_class_unknown_literal(void)
{
	return "unknown";
}

static const char* wc_preclass_class_allocated_literal(void)
{
	return "allocated";
}

static const char* wc_preclass_class_legacy_literal(void)
{
	return "legacy";
}

static const char* wc_preclass_class_reserved_literal(void)
{
	return "reserved";
}

static const char* wc_preclass_class_special_literal(void)
{
	return "special";
}

static const char* wc_preclass_class_unallocated_literal(void)
{
	return "unallocated";
}

static const char* wc_preclass_rir_unknown_literal(void)
{
	return "unknown";
}

static const char* wc_preclass_rir_none_literal(void)
{
	return "none";
}

static const char* wc_preclass_rir_apnic_literal(void)
{
	return "apnic";
}

static const char* wc_preclass_rir_arin_literal(void)
{
	return "arin";
}

static const char* wc_preclass_rir_ripe_literal(void)
{
	return "ripe";
}

static const char* wc_preclass_rir_afrinic_literal(void)
{
	return "afrinic";
}

static const char* wc_preclass_rir_lacnic_literal(void)
{
	return "lacnic";
}

static const char* wc_preclass_confidence_low_literal(void)
{
	return "low";
}

static const char* wc_preclass_confidence_medium_literal(void)
{
	return "medium";
}

static const char* wc_preclass_confidence_high_literal(void)
{
	return "high";
}

static const char* wc_preclass_reason_rir_hint_literal(void)
{
	return "RIR_HINT_FROM_EXISTING_GUESS";
}

static const char* wc_preclass_reason_no_rir_hint_literal(void)
{
	return "NO_RIR_HINT";
}

static const char* wc_preclass_reason_unknown_literal(void)
{
	return "PRECLASS_REASON_UNKNOWN";
}

static const char* wc_preclass_class_allocated_hint_literal(void)
{
	return wc_preclass_class_allocated_literal();
}

static const char* wc_preclass_class_unknown_hint_literal(void)
{
	return wc_preclass_class_unknown_literal();
}

static const char* wc_preclass_rir_unknown_hint_literal(void)
{
	return wc_preclass_rir_unknown_literal();
}

static const char* wc_preclass_confidence_medium_hint_literal(void)
{
	return wc_preclass_confidence_medium_literal();
}

static const char* wc_preclass_confidence_low_hint_literal(void)
{
	return wc_preclass_confidence_low_literal();
}

static const char* wc_preclass_reason_rir_hint_value_literal(void)
{
	return wc_preclass_reason_rir_hint_literal();
}

static const char* wc_preclass_reason_no_rir_hint_value_literal(void)
{
	return wc_preclass_reason_no_rir_hint_literal();
}



static void wc_preclass_set_allocated_hint(const char* normalized,
		const char** cls,
		const char** rir,
		const char** reason,
		const char** confidence);

static const char* wc_preclass_rir_unknown_compare_literal(void)
{
	return wc_preclass_rir_unknown_hint_literal();
}

static int wc_preclass_is_unknown_class_value(const char* cls)
{
	return wc_preclass_token_equals(cls, wc_preclass_class_unknown_hint_literal());
}

static int wc_preclass_has_rir_hint_value(const char* guessed_rir)
{
	return wc_preclass_has_text_value(guessed_rir) &&
		strcmp(guessed_rir, wc_preclass_rir_unknown_compare_literal()) != 0;
}

static void wc_preclass_set_v6_global_unicast_result(const char* normalized,
		const char** cls,
		const char** rir,
		const char** reason,
		const char** confidence)
{
	*cls = wc_preclass_class_allocated_literal();
	*reason = "V6_GLOBAL_UNICAST_2000_3";
	const char* guessed_rir = wc_guess_rir(normalized);
	if (wc_preclass_has_rir_hint_value(guessed_rir)) {
		*rir = guessed_rir;
		*confidence = wc_preclass_confidence_medium_literal();
	} else {
		*rir = wc_preclass_rir_unknown_compare_literal();
		*confidence = wc_preclass_confidence_low_literal();
	}
}

static void wc_preclass_set_unknown_hint_tuple(const char** cls,
		const char** rir,
		const char** reason,
		const char** confidence,
		const char* reason_value)
{
	*cls = wc_preclass_class_unknown_hint_literal();
	*rir = wc_preclass_rir_unknown_compare_literal();
	*reason = reason_value;
	*confidence = wc_preclass_confidence_low_hint_literal();
}

static int wc_preclass_v6_unknown_hint_required(const char* cls)
{
	return wc_preclass_is_unknown_class_value(cls);
}

static const char* wc_preclass_v6_unknown_hint_reason_literal(void)
{
	return wc_preclass_reason_no_rir_hint_value_literal();
}

static void wc_preclass_set_v6_unknown_hint_result(const char** cls,
		const char** rir,
		const char** reason,
		const char** confidence)
{
	if (wc_preclass_v6_unknown_hint_required(*cls))
		wc_preclass_set_unknown_hint_tuple(cls, rir, reason, confidence, wc_preclass_v6_unknown_hint_reason_literal());
}

static void wc_preclass_apply_v4_unknown_hint_if_needed(const char* normalized,
		const char** cls,
		const char** rir,
		const char** reason,
		const char** confidence)
{
	if (wc_preclass_is_unknown_class_value(*cls))
		wc_preclass_set_allocated_hint(normalized, cls, rir, reason, confidence);
}

static const char* wc_preclass_unknown_hint_default_reason_literal(void)
{
	return wc_preclass_reason_no_rir_hint_value_literal();
}

static void wc_preclass_set_unknown_hint_default(const char** cls,
		const char** rir,
		const char** reason,
		const char** confidence)
{
	*cls = wc_preclass_class_unknown_literal();
	*rir = wc_preclass_rir_unknown_literal();
	*reason = wc_preclass_unknown_hint_default_reason_literal();
	*confidence = wc_preclass_confidence_low_literal();
}

static int wc_preclass_apply_allocated_hint_from_rir(const char* guessed_rir)
{
	return guessed_rir && *guessed_rir && strcmp(guessed_rir, wc_preclass_rir_unknown_compare_literal()) != 0;
}

static void wc_preclass_set_allocated_hint(const char* normalized,
		const char** cls,
		const char** rir,
		const char** reason,
		const char** confidence)
{
	const char* guessed_rir = wc_guess_rir(normalized);
	if (wc_preclass_apply_allocated_hint_from_rir(guessed_rir)) {
		*cls = wc_preclass_class_allocated_hint_literal();
		*rir = guessed_rir;
		*reason = wc_preclass_reason_rir_hint_value_literal();
		*confidence = wc_preclass_confidence_medium_hint_literal();
		return;
	}
	wc_preclass_set_unknown_hint_default(cls, rir, reason, confidence);
}

static void wc_preclass_set_special_tuple(const char** cls,
        const char** rir,
        const char** reason,
        const char** confidence,
        const char* reason_value);

static void wc_preclass_set_v6_branch_special_result(const char** cls,
        const char** rir,
        const char** reason,
        const char** confidence,
        const char* reason_value)
{
    wc_preclass_set_special_tuple(cls, rir, reason, confidence, reason_value);
}

static int wc_preclass_is_v6_loopback(const struct in6_addr* addr6)
{
	if (!addr6)
		return 0;
	for (int i = 0; i < 15; ++i) {
		if (addr6->s6_addr[i] != 0)
			return 0;
	}
	return addr6->s6_addr[15] == 1;
}

static uint64_t wc_preclass_read_be64(const unsigned char* bytes)
{
	if (!bytes)
		return 0;
	return (((uint64_t)bytes[0]) << 56) |
		(((uint64_t)bytes[1]) << 48) |
		(((uint64_t)bytes[2]) << 40) |
		(((uint64_t)bytes[3]) << 32) |
		(((uint64_t)bytes[4]) << 24) |
		(((uint64_t)bytes[5]) << 16) |
		(((uint64_t)bytes[6]) << 8) |
		((uint64_t)bytes[7]);
}

enum {
	WC_PRECLASS_CLASS_ID_UNKNOWN = 0u,
	WC_PRECLASS_CLASS_ID_ALLOCATED = 1u,
	WC_PRECLASS_CLASS_ID_LEGACY = 2u,
	WC_PRECLASS_CLASS_ID_RESERVED = 3u,
	WC_PRECLASS_CLASS_ID_SPECIAL = 4u,
	WC_PRECLASS_CLASS_ID_UNALLOCATED = 5u
};

static const char* wc_preclass_class_name(uint8_t class_id)
{
	switch (class_id) {
		case WC_PRECLASS_CLASS_ID_UNKNOWN: return wc_preclass_class_unknown_literal();
		case WC_PRECLASS_CLASS_ID_ALLOCATED: return wc_preclass_class_allocated_literal();
		case WC_PRECLASS_CLASS_ID_LEGACY: return wc_preclass_class_legacy_literal();
		case WC_PRECLASS_CLASS_ID_RESERVED: return wc_preclass_class_reserved_literal();
		case WC_PRECLASS_CLASS_ID_SPECIAL: return wc_preclass_class_special_literal();
		case WC_PRECLASS_CLASS_ID_UNALLOCATED: return wc_preclass_class_unallocated_literal();
		default: return wc_preclass_class_unknown_literal();
	}
}

enum {
	WC_PRECLASS_RIR_ID_UNKNOWN = 0u,
	WC_PRECLASS_RIR_ID_NONE = 1u,
	WC_PRECLASS_RIR_ID_APNIC = 2u,
	WC_PRECLASS_RIR_ID_ARIN = 3u,
	WC_PRECLASS_RIR_ID_RIPE = 4u,
	WC_PRECLASS_RIR_ID_AFRINIC = 5u,
	WC_PRECLASS_RIR_ID_LACNIC = 6u
};

static const char* wc_preclass_rir_name(uint8_t rir_id)
{
	switch (rir_id) {
		case WC_PRECLASS_RIR_ID_UNKNOWN: return wc_preclass_rir_unknown_literal();
		case WC_PRECLASS_RIR_ID_NONE: return wc_preclass_rir_none_literal();
		case WC_PRECLASS_RIR_ID_APNIC: return wc_preclass_rir_apnic_literal();
		case WC_PRECLASS_RIR_ID_ARIN: return wc_preclass_rir_arin_literal();
		case WC_PRECLASS_RIR_ID_RIPE: return wc_preclass_rir_ripe_literal();
		case WC_PRECLASS_RIR_ID_AFRINIC: return wc_preclass_rir_afrinic_literal();
		case WC_PRECLASS_RIR_ID_LACNIC: return wc_preclass_rir_lacnic_literal();
		default: return wc_preclass_rir_unknown_literal();
	}
}

enum {
	WC_PRECLASS_CONFIDENCE_ID_LOW = 0u,
	WC_PRECLASS_CONFIDENCE_ID_MEDIUM = 1u,
	WC_PRECLASS_CONFIDENCE_ID_HIGH = 2u
};

static const char* wc_preclass_confidence_name(uint8_t confidence_id)
{
	switch (confidence_id) {
		case WC_PRECLASS_CONFIDENCE_ID_LOW: return wc_preclass_confidence_low_literal();
		case WC_PRECLASS_CONFIDENCE_ID_MEDIUM: return wc_preclass_confidence_medium_literal();
		case WC_PRECLASS_CONFIDENCE_ID_HIGH: return wc_preclass_confidence_high_literal();
		default: return wc_preclass_confidence_low_literal();
	}
}

enum {
	WC_PRECLASS_REASON_ID_V4_ALLOCATED = 1001u,
	WC_PRECLASS_REASON_ID_V4_LEGACY = 1002u,
	WC_PRECLASS_REASON_ID_V4_RESERVED = 1003u,
	WC_PRECLASS_REASON_ID_V4_UNKNOWN = 1099u,
	WC_PRECLASS_REASON_ID_V6_GLOBAL_UNICAST = 2001u,
	WC_PRECLASS_REASON_ID_V6_UNIQUE_LOCAL = 2002u,
	WC_PRECLASS_REASON_ID_V6_LINK_LOCAL = 2003u,
	WC_PRECLASS_REASON_ID_V6_MULTICAST = 2004u,
	WC_PRECLASS_REASON_ID_V6_RESERVED = 2005u,
	WC_PRECLASS_REASON_ID_V6_UNKNOWN = 2099u
};

static const char* wc_preclass_reason_name(uint16_t reason_id)
{
	switch (reason_id) {
		case WC_PRECLASS_REASON_ID_V4_ALLOCATED: return "V4_ALLOCATED_REGISTRY";
		case WC_PRECLASS_REASON_ID_V4_LEGACY: return "V4_LEGACY_REGISTRY";
		case WC_PRECLASS_REASON_ID_V4_RESERVED: return "V4_RESERVED_REGISTRY";
		case WC_PRECLASS_REASON_ID_V4_UNKNOWN: return "V4_UNKNOWN_REGISTRY";
		case WC_PRECLASS_REASON_ID_V6_GLOBAL_UNICAST: return "V6_GLOBAL_UNICAST_2000_3";
		case WC_PRECLASS_REASON_ID_V6_UNIQUE_LOCAL: return "V6_UNIQUE_LOCAL_FC00_7";
		case WC_PRECLASS_REASON_ID_V6_LINK_LOCAL: return "V6_LINK_LOCAL_FE80_10";
		case WC_PRECLASS_REASON_ID_V6_MULTICAST: return "V6_MULTICAST_FF00_8";
		case WC_PRECLASS_REASON_ID_V6_RESERVED: return "V6_RESERVED_IETF";
		case WC_PRECLASS_REASON_ID_V6_UNKNOWN: return "V6_UNKNOWN_REGISTRY";
		default: return wc_preclass_reason_unknown_literal();
	}
}

static int wc_preclass_lookup_row_v4(uint32_t addr, const wc_preclass_table_row_t** out_row)
{
	size_t i;

	if (!out_row)
		return 0;
	*out_row = NULL;

	for (i = 0; i < wc_preclass_table_count; ++i) {
		const wc_preclass_table_row_t* row = &wc_preclass_table[i];
		uint8_t prefix_len;
		uint32_t row_addr;
		uint32_t mask;

		if (row->family == 6u)
			break;
		if (row->family != 4u)
			continue;

		prefix_len = row->prefix_len;
		if (prefix_len > 32u)
			continue;

		row_addr = (uint32_t)(row->addr_lo & 0xFFFFFFFFu);
		if (prefix_len == 0u) {
			*out_row = row;
			return 1;
		}

		mask = (prefix_len == 32u)
			? 0xFFFFFFFFu
			: (0xFFFFFFFFu << (32u - prefix_len));
		if ((addr & mask) == (row_addr & mask)) {
			*out_row = row;
			return 1;
		}
	}

	return 0;
}

static int wc_preclass_lookup_row_v6(uint64_t hi,
		uint64_t lo,
		const wc_preclass_table_row_t** out_row)
{
	size_t i;

	if (!out_row)
		return 0;
	*out_row = NULL;

	for (i = 0; i < wc_preclass_table_count; ++i) {
		const wc_preclass_table_row_t* row = &wc_preclass_table[i];
		uint8_t prefix_len;

		if (row->family != 6u)
			continue;

		prefix_len = row->prefix_len;
		if (prefix_len > 128u)
			continue;

		if (prefix_len == 0u) {
			*out_row = row;
			return 1;
		}

		if (prefix_len <= 64u) {
			uint64_t mask_hi = (prefix_len == 64u)
				? 0xFFFFFFFFFFFFFFFFULL
				: (0xFFFFFFFFFFFFFFFFULL << (64u - prefix_len));
			if ((hi & mask_hi) == (row->addr_hi & mask_hi)) {
				*out_row = row;
				return 1;
			}
			continue;
		}

		if (hi != row->addr_hi)
			continue;

		uint8_t rem = (uint8_t)(prefix_len - 64u);
		uint64_t mask_lo = (rem == 64u)
			? 0xFFFFFFFFFFFFFFFFULL
			: (0xFFFFFFFFFFFFFFFFULL << (64u - rem));
		if ((lo & mask_lo) == (row->addr_lo & mask_lo)) {
			*out_row = row;
			return 1;
		}
	}

	return 0;
}

static void wc_preclass_assign_from_row(const wc_preclass_table_row_t* row,
		const char** cls,
		const char** rir,
		const char** reason,
		const char** confidence)
{
	if (!row || !cls || !rir || !reason || !confidence)
		return;
	*cls = wc_preclass_class_name(row->class_id);
	*rir = wc_preclass_rir_name(row->rir_id);
	*reason = wc_preclass_reason_name(row->reason_id);
	*confidence = wc_preclass_confidence_name(row->confidence_id);
}

static const char* wc_preclass_family_v4_literal(void)
{
	return "v4";
}

static const char* wc_preclass_family_v6_literal(void)
{
	return "v6";
}

static const char* wc_preclass_family_non_ip_literal(void)
{
	return "non-ip";
}

static int wc_preclass_lookup_table(const char* normalized,
		const char** family,
		const char** cls,
		const char** rir,
		const char** reason,
		const char** confidence)
{
	struct in_addr addr4;
	struct in6_addr addr6;

	if (!normalized || !family || !cls || !rir || !reason || !confidence)
		return 0;

	if (inet_pton(AF_INET, normalized, &addr4) == 1) {
		const wc_preclass_table_row_t* row;
		unsigned char b[4];
		uint32_t ip;
		memcpy(b, &addr4, sizeof(b));
		ip = (((uint32_t)b[0]) << 24) |
			(((uint32_t)b[1]) << 16) |
			(((uint32_t)b[2]) << 8) |
			((uint32_t)b[3]);
		if (!wc_preclass_lookup_row_v4(ip, &row))
			return 0;
		*family = wc_preclass_family_v4_literal();
		wc_preclass_assign_from_row(row, cls, rir, reason, confidence);
		return 1;
	}

	if (inet_pton(AF_INET6, normalized, &addr6) == 1) {
		const wc_preclass_table_row_t* row;
		const unsigned char* b = addr6.s6_addr;
		uint64_t hi = wc_preclass_read_be64(b);
		uint64_t lo = wc_preclass_read_be64(b + 8);
		if (!wc_preclass_lookup_row_v6(hi, lo, &row))
			return 0;
		*family = wc_preclass_family_v6_literal();
		wc_preclass_assign_from_row(row, cls, rir, reason, confidence);
		return 1;
	}

	return 0;
}

static void wc_preclass_set_special_tuple(const char** cls,
		const char** rir,
		const char** reason,
		const char** confidence,
		const char* reason_value)
{
	*cls = wc_preclass_class_special_literal();
	*rir = wc_preclass_rir_none_literal();
	*reason = reason_value;
	*confidence = wc_preclass_confidence_high_literal();
}

static void wc_preclass_apply_special_result(const char** cls,
		const char** rir,
		const char** reason,
		const char** confidence,
		const char* reason_value)
{
	wc_preclass_set_special_tuple(cls, rir, reason, confidence, reason_value);
}

static void wc_preclass_set_v4_special_result(const char** cls,
		const char** rir,
		const char** reason,
		const char** confidence,
		const char* reason_value)
{
	wc_preclass_apply_special_result(cls, rir, reason, confidence, reason_value);
}

static const char* wc_preclass_v4_limited_broadcast_reason_literal(void)
{
	return "V4_LIMITED_BROADCAST_255_255_255_255";
}

static const char* wc_preclass_v4_this_network_reason_literal(void)
{
	return "V4_THIS_NETWORK_0_8";
}

static const char* wc_preclass_v4_link_local_reason_literal(void)
{
	return "V4_LINK_LOCAL_169_254_16";
}

static const char* wc_preclass_v6_loopback_reason_literal(void)
{
	return "V6_LOOPBACK_1";
}

static const char* wc_preclass_v4_reserved_future_use_reason_literal(void)
{
	return "V4_FUTURE_USE_240_4";
}

static void wc_preclass_set_reserved_none_tuple(const char** cls,
		const char** rir,
		const char** reason,
		const char** confidence,
		const char* reason_value)
{
	*cls = wc_preclass_class_reserved_literal();
	*rir = wc_preclass_rir_none_literal();
	*reason = reason_value;
	*confidence = wc_preclass_confidence_high_literal();
}

static void wc_preclass_set_v4_reserved_future_use_result(const char** cls,
		const char** rir,
		const char** reason,
		const char** confidence)
{
	wc_preclass_set_reserved_none_tuple(
		cls,
		rir,
		reason,
		confidence,
		wc_preclass_v4_reserved_future_use_reason_literal());
}

static void wc_preclass_set_v4_private_range_result(const char** cls, const char** rir, const char** reason, const char** confidence, const char* reason_value)
{
	wc_preclass_set_special_tuple(cls, rir, reason, confidence, reason_value);
}

static const char* wc_preclass_v4_private_172_reason_literal(void)
{
	return "V4_PRIVATE_172_16_12";
}

static const char* wc_preclass_v4_private_192_reason_literal(void)
{
	return "V4_PRIVATE_192_168_16";
}

static int wc_preclass_v4_is_limited_broadcast(const unsigned char* b)
{
	return b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255;
}

static int wc_preclass_v4_is_future_use(const unsigned char* b)
{
	return b[0] >= 240;
}

static int wc_preclass_v4_is_this_network(const unsigned char* b)
{
	return b[0] == 0;
}

static int wc_preclass_v4_is_private_10_8(const unsigned char* b)
{
	return b[0] == 10;
}

static int wc_preclass_v4_is_loopback(const unsigned char* b)
{
	return b[0] == 127;
}

static const char* wc_preclass_v6_link_local_reason_literal(void)
{
	return "V6_LINK_LOCAL_FE80_10";
}

static void wc_preclass_set_v6_loopback_result(const char** cls, const char** rir, const char** reason, const char** confidence)
{
	*cls = wc_preclass_class_special_literal();
	*rir = wc_preclass_rir_none_literal();
	*reason = wc_preclass_v6_loopback_reason_literal();
	*confidence = wc_preclass_confidence_high_literal();
}

static int wc_preclass_v6_is_unique_local(const unsigned char* b)
{
	return (b[0] & 0xFE) == 0xFC;
}

static int wc_preclass_v6_is_link_local(const unsigned char* b)
{
	return b[0] == 0xFE && (b[1] & 0xC0) == 0x80;
}

static int wc_preclass_v6_is_multicast(const unsigned char* b)
{
	return b[0] == 0xFF;
}

static int wc_preclass_v6_is_documentation(const unsigned char* b)
{
	return b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8;
}

static int wc_preclass_v6_is_global_unicast_2000_3(const unsigned char* b)
{
	return (b[0] & 0xE0) == 0x20;
}

static void wc_preclass_set_non_ip_defaults(const char** family, const char** cls, const char** rir, const char** reason, const char** confidence)
{
	*family = wc_preclass_family_non_ip_literal();
	*cls = "unknown";
	*rir = "unknown";
	*reason = "NON_IP_INPUT";
	*confidence = "low";
}

void wc_preclass_classify_ip(const char* normalized,
		const char** family,
		const char** cls,
		const char** rir,
		const char** reason,
		const char** confidence)
{
	if (!normalized || !family || !cls || !rir || !reason || !confidence)
		return;

	wc_preclass_set_non_ip_defaults(family, cls, rir, reason, confidence);

	(void)wc_preclass_lookup_table(normalized,
		family,
		cls,
		rir,
		reason,
		confidence);

	struct in_addr addr4;
	if (inet_pton(AF_INET, normalized, &addr4) == 1) {
		unsigned char b[4];
		memcpy(b, &addr4, sizeof(b));
		*family = wc_preclass_family_v4_literal();

		if (wc_preclass_v4_is_limited_broadcast(b)) {
			wc_preclass_set_v4_special_result(cls, rir, reason, confidence, wc_preclass_v4_limited_broadcast_reason_literal());
			return;
		}
		if (wc_preclass_v4_is_future_use(b)) {
			wc_preclass_set_v4_reserved_future_use_result(cls, rir, reason, confidence);
			return;
		}
		if (wc_preclass_v4_is_this_network(b)) {
			wc_preclass_set_v4_special_result(cls, rir, reason, confidence, wc_preclass_v4_this_network_reason_literal());
			return;
		}
		if (wc_preclass_v4_is_private_10_8(b)) {
			wc_preclass_set_special_tuple(cls, rir, reason, confidence, "V4_PRIVATE_10_8");
			return;
		}
		if (wc_preclass_v4_is_loopback(b)) {
			wc_preclass_set_special_tuple(cls, rir, reason, confidence, "V4_LOOPBACK_127_8");
			return;
		}
		if (b[0] == 169 && b[1] == 254) {
			wc_preclass_set_special_tuple(cls, rir, reason, confidence, wc_preclass_v4_link_local_reason_literal());
			return;
		}
		if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) {
			wc_preclass_set_v4_private_range_result(cls, rir, reason, confidence, wc_preclass_v4_private_172_reason_literal());
			return;
		}
		if (b[0] == 192 && b[1] == 168) {
			wc_preclass_set_v4_private_range_result(cls, rir, reason, confidence, wc_preclass_v4_private_192_reason_literal());
			return;
		}
		if (b[0] >= 224 && b[0] <= 239) {
			wc_preclass_set_special_tuple(cls, rir, reason, confidence, "V4_MULTICAST_224_4");
			return;
		}

		wc_preclass_apply_v4_unknown_hint_if_needed(normalized, cls, rir, reason, confidence);
		return;
	}

	struct in6_addr addr6;
	if (inet_pton(AF_INET6, normalized, &addr6) == 1) {
		const unsigned char* b = addr6.s6_addr;
		*family = wc_preclass_family_v6_literal();

		if (wc_preclass_is_v6_loopback(&addr6)) {
			wc_preclass_set_v6_loopback_result(cls, rir, reason, confidence);
			return;
		}
		if (wc_preclass_v6_is_unique_local(b)) {
			wc_preclass_set_v6_branch_special_result(cls, rir, reason, confidence, "V6_UNIQUE_LOCAL_FC00_7");
			return;
		}
		if (wc_preclass_v6_is_link_local(b)) {
			wc_preclass_set_v6_branch_special_result(cls, rir, reason, confidence, wc_preclass_v6_link_local_reason_literal());
			return;
		}
		if (wc_preclass_v6_is_multicast(b)) {
			wc_preclass_set_v6_branch_special_result(cls, rir, reason, confidence, "V6_MULTICAST_FF00_8");
			return;
		}
		if (wc_preclass_v6_is_documentation(b)) {
			wc_preclass_set_v6_branch_special_result(cls, rir, reason, confidence, "V6_DOCUMENTATION_2001_DB8_32");
			return;
		}
		if (wc_preclass_v6_is_global_unicast_2000_3(b)) {
			wc_preclass_set_v6_global_unicast_result(normalized, cls, rir, reason, confidence);
			return;
		}

		wc_preclass_set_v6_unknown_hint_result(cls, rir, reason, confidence);
		return;
	}
}