// Core helpers for executing a single WHOIS query and applying
// title/grep/sanitize filters. Logic is migrated from whois_client.c
// without behavior changes.

#include <stdio.h>
#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "wc/wc_query_exec.h"
#include "wc/wc_debug.h"
#include "wc/wc_net.h"
#include "wc/wc_server.h"
#include "wc/wc_dns.h"
#include "wc/wc_seclog.h"
#include "wc/wc_lookup.h"
#include "wc/wc_output.h"
#include "wc/wc_fold.h"
#include "wc/wc_config.h"
#include "wc/wc_util.h"
#include "wc/wc_cache.h"
#include "wc/wc_runtime.h"
extern Config g_config;

// Security event type used with log_security_event (defined in whois_client.c)
#ifndef SEC_EVENT_SUSPICIOUS_QUERY
#define SEC_EVENT_SUSPICIOUS_QUERY 2
#endif

// Local helpers moved from whois_client.c
static int detect_suspicious_query(const char* query) {
	if (!query || !*query)
		return 0;
	const char* suspicious_patterns[] = {
		"..",         // Directory traversal
		";",          // Command injection
		"|",          // Pipe injection
		"&&",         // Command chaining
		"||",         // Command chaining
		"`",          // Command substitution
		"$",          // Variable substitution
		"(",          // Command grouping
		")",          // Command grouping
		"\\n",        // Newline injection
		"\\r",        // Carriage return injection
		"\\0",        // Null byte injection
		"--",         // SQL/command comment
		"/*",         // SQL comment start
		"*/",         // SQL comment end
		"<",          // Input redirection
		">",          // Output redirection
		NULL
	};
	for (int i = 0; suspicious_patterns[i] != NULL; i++) {
		if (strstr(query, suspicious_patterns[i])) {
			log_security_event(SEC_EVENT_SUSPICIOUS_QUERY,
				"Detected suspicious pattern '%s' in query: %s",
				suspicious_patterns[i], query);
			return 1;
		}
	}
	if (strlen(query) > 1024) {
		log_security_event(SEC_EVENT_SUSPICIOUS_QUERY,
			"Overly long query detected (%zu chars): %.100s...",
			strlen(query), query);
		return 1;
	}
	for (const char* p = query; *p; p++) {
		if ((unsigned char)*p < 32 && *p != '\n' && *p != '\r' && *p != '\t') {
			log_security_event(SEC_EVENT_SUSPICIOUS_QUERY,
				"Binary data detected in query at position %ld: 0x%02x",
				p - query, (unsigned char)*p);
			return 1;
		}
	}
	return 0;
}

static char* sanitize_response_for_output(const char* input) {
	if (!input)
		return (char*)wc_safe_malloc(1, "sanitize_response_for_output_empty");
	size_t len = strlen(input);
	char* output = wc_safe_malloc(len + 1,
		"sanitize_response_for_output");
	size_t out_pos = 0;
	int in_escape = 0;
	for (size_t i = 0; i < len; i++) {
		unsigned char c = input[i];
		if (c == 0) {
			continue;
		} else if (c < 32 && c != '\n' && c != '\r' && c != '\t') {
			output[out_pos++] = ' ';
		} else if (c == '\033') {
			in_escape = 1;
			continue;
		} else if (in_escape) {
			if ((c >= 'A' && c <= 'Z') ||
				(c >= 'a' && c <= 'z')) {
				in_escape = 0;
			}
			continue;
		} else {
			output[out_pos++] = c;
		}
	}
	output[out_pos] = '\0';
	if (out_pos != len && g_config.debug) {
		wc_output_log_message("DEBUG",
			"Sanitized response: removed %zu problematic characters",
			len - out_pos);
	}
	return output;
}

int wc_execute_lookup(const char* query,
		const char* server_host,
		int port,
		struct wc_result* out_res) {
	if (!out_res || !query)
		return -1;
	struct wc_query q = { .raw = query, .start_server = server_host, .port = port };
	struct wc_lookup_opts lopts = { .max_hops = g_config.max_redirects,
		.no_redirect = g_config.no_redirect,
		.timeout_sec = g_config.timeout_sec,
		.retries = g_config.max_retries };
	memset(out_res, 0, sizeof(*out_res));
	return wc_lookup_execute(&q, &lopts, out_res);
}

int wc_handle_suspicious_query(const char* query, int in_batch) {
	if (!detect_suspicious_query(query))
		return 0;
	if (in_batch) {
		log_security_event(SEC_EVENT_SUSPICIOUS_QUERY,
			"Blocked suspicious query in batch mode: %s", query);
		fprintf(stderr,
			"Error: Suspicious query detected in batch mode: %s\n",
			query);
		return 1;
	}
	log_security_event(SEC_EVENT_SUSPICIOUS_QUERY,
		"Blocked suspicious query: %s", query);
	fprintf(stderr, "Error: Suspicious query detected\n");
	wc_cache_cleanup();
	return 1;
}

int wc_handle_private_ip(const char* query, const char* ip, int in_batch) {
	(void)in_batch;
	if (g_config.fold_output) {
		char* folded = wc_fold_build_line(
			"", query, "unknown",
			g_config.fold_sep ? g_config.fold_sep : " ",
			g_config.fold_upper);
		printf("%s", folded);
		free(folded);
	} else {
		if (!g_config.plain_mode) {
			wc_output_header_plain(query);
		}
		printf("%s is a private IP address\n", query);
		if (!g_config.plain_mode) {
			wc_output_tail_unknown_plain();
		}
	}
	(void)ip;
	return 0;
}

void wc_report_query_failure(const char* query,
		const char* server_host,
		int err) {
	const struct wc_result* res = NULL;
	int lerr = err;
	if (lerr) {
		const char* cause = NULL;
		switch (lerr) {
		case ETIMEDOUT:
			cause = "connect timeout";
			break;
		case ECONNREFUSED:
			cause = "connection refused";
			break;
		case ENETUNREACH:
			cause = "network unreachable";
			break;
		case EHOSTUNREACH:
			cause = "host unreachable";
			break;
		case EADDRNOTAVAIL:
			cause = "address not available";
			break;
		case EINTR:
			cause = "interrupted";
			break;
		default:
			cause = strerror(lerr);
			break;
		}
		fprintf(stderr,
			"Error: Query failed for %s (%s, errno=%d)\n",
			query, cause, lerr);
	} else {
		fprintf(stderr, "Error: Query failed for %s\n", query);
	}

	if (!g_config.fold_output && !g_config.plain_mode && res) {
		const char* via_host = res->meta.via_host[0]
			? res->meta.via_host
			: (server_host ? server_host : "whois.iana.org");
		const char* via_ip = res->meta.via_ip[0] ? res->meta.via_ip : NULL;
		if (via_ip)
			wc_output_header_via_ip(query, via_host, via_ip);
		else
			wc_output_header_via_unknown(query, via_host);
		const char* auth_host =
			(res->meta.authoritative_host[0]
				? res->meta.authoritative_host
				: "unknown");
		const char* auth_ip =
			(res->meta.authoritative_ip[0]
				? res->meta.authoritative_ip
				: "unknown");
		if (strcmp(auth_host, "unknown") == 0 &&
				strcmp(auth_ip, "unknown") == 0) {
			wc_output_tail_unknown_unknown();
		} else {
			wc_output_tail_authoritative_ip(auth_host, auth_ip);
		}
	}
}

char* wc_apply_response_filters(const char* query,
		const char* raw_response,
		int in_batch) {
	(void)query;
    if (!raw_response)
        return NULL;
    size_t len = strlen(raw_response) + 1;
    char* result = (char*)wc_safe_malloc(len, __func__);
    memcpy(result, raw_response, len);

	if (wc_title_is_enabled()) {
		if (wc_is_debug_enabled()) {
			fprintf(stderr,
				in_batch ? "[TRACE][batch] stage=title_filter in\n"
				        : "[TRACE] stage=title_filter in\n");
		}
		char* filtered = wc_title_filter_response(result);
		if (wc_is_debug_enabled()) {
			fprintf(stderr,
				in_batch ? "[TRACE][batch] stage=title_filter out ptr=%p\n"
				        : "[TRACE] stage=title_filter out ptr=%p\n",
				(void*)filtered);
		}
		free(result);
		result = filtered;
	}

	if (wc_grep_is_enabled()) {
		if (wc_is_debug_enabled()) {
			fprintf(stderr,
				in_batch ? "[TRACE][batch] stage=grep_filter in\n"
				        : "[TRACE] stage=grep_filter in\n");
		}
		char* f2 = wc_grep_filter(result);
		if (wc_is_debug_enabled()) {
			fprintf(stderr,
				in_batch ? "[TRACE][batch] stage=grep_filter out ptr=%p\n"
				        : "[TRACE] stage=grep_filter out ptr=%p\n",
				(void*)f2);
		}
		free(result);
		result = f2;
	}

	if (wc_is_debug_enabled()) {
		fprintf(stderr,
			in_batch ? "[TRACE][batch] stage=sanitize in ptr=%p\n"
			        : "[TRACE] stage=sanitize in ptr=%p\n",
			(void*)result);
	}
	char* sanitized_result = sanitize_response_for_output(result);
	free(result);
	result = sanitized_result;
	if (wc_is_debug_enabled()) {
		fprintf(stderr,
			in_batch ? "[TRACE][batch] stage=sanitize out ptr=%p len=%zu\n"
			        : "[TRACE] stage=sanitize out ptr=%p len=%zu\n",
			(void*)result, strlen(result));
	}
	return result;
}

// High-level single-query orchestrator used by whois_client.c.
// This mirrors the legacy wc_run_single_query behavior while
// delegating shared pieces to the helpers above.
int wc_client_run_single_query(const char* query,
		const char* server_host,
		int port) {
	// Security: detect suspicious queries
	if (wc_handle_suspicious_query(query, 0))
		return 1;

	struct wc_result res;
	int lrc = wc_execute_lookup(query, server_host, port, &res);
	int rc = 1;

	if (g_config.debug)
		printf("[DEBUG] ===== MAIN QUERY START (lookup) =====\n");
	if (!lrc && res.body) {
		char* result = res.body;
		res.body = NULL;
		if (wc_is_debug_enabled())
			fprintf(stderr,
				"[TRACE] after header; body_ptr=%p len=%zu (stage=initial)\n",
				(void*)result, res.body_len);
		if (!g_config.fold_output && !g_config.plain_mode) {
			const char* via_host = res.meta.via_host[0]
				? res.meta.via_host
				: (server_host ? server_host : "whois.iana.org");
			const char* via_ip = res.meta.via_ip[0]
				? res.meta.via_ip
				: NULL;
			if (via_ip)
				wc_output_header_via_ip(query, via_host, via_ip);
			else
				wc_output_header_via_unknown(query, via_host);
		}
		char* filtered = wc_apply_response_filters(query, result, 0);
		free(result);
		result = filtered;

		char* authoritative_display_owned = NULL;
		const char* authoritative_display =
			(res.meta.authoritative_host[0]
				? res.meta.authoritative_host
				: NULL);
		if (authoritative_display && wc_dns_is_ip_literal(authoritative_display)) {
			char* mapped = wc_dns_rir_fallback_from_ip(authoritative_display);
			if (mapped) {
				authoritative_display_owned = mapped;
				authoritative_display = mapped;
			}
		}

		if (g_config.fold_output) {
			const char* rirv =
				(authoritative_display && *authoritative_display)
					? authoritative_display
					: "unknown";
			char* folded = wc_fold_build_line(
				result, query, rirv,
				g_config.fold_sep ? g_config.fold_sep : " ",
				g_config.fold_upper);
			printf("%s", folded);
			free(folded);
		} else {
			printf("%s", result);
			if (!g_config.plain_mode) {
				if (authoritative_display && *authoritative_display) {
					const char* auth_ip =
						(res.meta.authoritative_ip[0]
							? res.meta.authoritative_ip
							: "unknown");
					wc_output_tail_authoritative_ip(authoritative_display,
						auth_ip);
				} else {
					wc_output_tail_unknown_unknown();
				}
			}
		}
		if (authoritative_display_owned)
			free(authoritative_display_owned);
		free(result);
		rc = 0;
	} else {
		wc_report_query_failure(query, server_host,
			res.meta.last_connect_errno);
		wc_cache_cleanup();
	}
	wc_lookup_result_free(&res);
	wc_runtime_housekeeping_tick();
	return rc;
}
