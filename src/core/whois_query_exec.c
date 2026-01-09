// Core helpers for executing a single WHOIS query and applying
// title/grep/sanitize filters. Logic is migrated from whois_client.c
// without behavior changes.

#include <stdio.h>
#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "wc/wc_query_exec.h"
#include "wc/wc_client_flow.h"
#include "wc/wc_client_util.h"
#include "wc/wc_debug.h"
#include "wc/wc_dns.h"
#include "wc/wc_fold.h"
#include "wc/wc_lookup.h"
#include "wc/wc_net.h"
#include "wc/wc_output.h"
#include "wc/wc_runtime.h"
#include "wc/wc_seclog.h"
#include "wc/wc_selftest.h"
#include "wc/wc_server.h"
#include "wc/wc_signal.h"
#include "wc/wc_util.h"
#include "wc/wc_cache.h"
#include "wc/wc_workbuf.h"

static int wc_query_exec_match_forced(const char* forced, const char* query)
{
	if (!forced || !query || !*query)
		return 0;
	if (forced[0] == '*' && forced[1] == '\0')
		return 1;
	return strcmp(forced, query) == 0;
}

static const wc_selftest_injection_t*
wc_query_exec_resolve_injection(const wc_net_context_t* net_ctx)
{
	if (net_ctx && net_ctx->injection)
		return net_ctx->injection;
	return wc_selftest_injection_view();
}

static const char* wc_client_resolve_authoritative_display(const Config* cfg,
        const struct wc_result* res,
        char** owned_out)
{
	if (owned_out)
		*owned_out = NULL;
	if (!res)
		return NULL;
	const char* authoritative_display =
		(res->meta.authoritative_host[0]
			? res->meta.authoritative_host
			: NULL);
	if (authoritative_display && wc_dns_is_ip_literal(authoritative_display)) {
		char* mapped = wc_dns_rir_fallback_from_ip(cfg, authoritative_display);
		if (mapped) {
			if (owned_out)
				*owned_out = mapped;
			return mapped;
		}
	}
	return authoritative_display;
}

static void wc_client_render_single_success(const Config* cfg,
        const wc_client_render_opts_t* render_opts,
        const char* query,
        const char* server_host,
        struct wc_result* res)
{
	char* raw_body = res->body;
	res->body = NULL;
	wc_workbuf_t filter_wb; wc_workbuf_init(&filter_wb);
	if (render_opts->debug)
		fprintf(stderr,
			"[TRACE] after header; body_ptr=%p len=%zu (stage=initial)\n",
			(void*)raw_body, res->body_len);
	if (!render_opts->fold_output && !render_opts->plain_mode) {
		const char* via_host = res->meta.via_host[0]
			? res->meta.via_host
			: (server_host ? server_host : "whois.iana.org");
		const char* via_ip = res->meta.via_ip[0]
			? res->meta.via_ip
			: NULL;
		if (via_ip)
			wc_output_header_via_ip(query, via_host, via_ip);
		else
			wc_output_header_via_unknown(query, via_host);
	}
	char* filtered = wc_apply_response_filters(cfg, query, raw_body, 0, &filter_wb);
	free(raw_body);

	char* authoritative_display_owned = NULL;
	const char* authoritative_display = wc_client_resolve_authoritative_display(
		cfg, res, &authoritative_display_owned);

	if (render_opts->fold_output) {
		const char* rirv =
			(authoritative_display && *authoritative_display)
				? authoritative_display
				: "unknown";
		char* folded = wc_fold_build_line_wb(
			filtered, query, rirv,
			render_opts->fold_sep,
			render_opts->fold_upper,
			&filter_wb);
		printf("%s", folded);
	} else {
		printf("%s", filtered);
		if (!render_opts->plain_mode) {
			if (authoritative_display && *authoritative_display) {
				const char* auth_ip =
					(res->meta.authoritative_ip[0]
						? res->meta.authoritative_ip
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
	wc_workbuf_free(&filter_wb);
}


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


static char* normalize_line_endings_inplace(char* buf) {
	if (!buf)
		return NULL;
	if (!strchr(buf, '\r'))
		return buf;
	char* dst = buf;
	for (char* src = buf; *src; ++src) {
		if (*src == '\r') {
			*dst++ = '\n';
			if (src[1] == '\n')
				++src; // collapse CRLF into single LF
		} else {
			*dst++ = *src;
		}
	}
	*dst = '\0';
	return buf;
}

static char* sanitize_response_for_output_wb(const Config* config, const char* input, wc_workbuf_t* wb) {
	int debug = config && config->debug;
	if (!input || !wb)
		return NULL;
	size_t len = strlen(input);
	char* output = wc_workbuf_reserve(wb, len, "sanitize_response_for_output");
	size_t out_pos = 0;
	int in_escape = 0;
	for (size_t i = 0; i < len; i++) {
		unsigned char c = input[i];
		if (c == 0)
			continue;
		if (c == '\r') {
			output[out_pos++] = '\n';
			if (i + 1 < len && input[i + 1] == '\n')
				++i; // collapse CRLF into a single LF
			continue;
		}
		if (c == '\n') {
			output[out_pos++] = '\n';
			continue;
		}
		if (c < 32 && c != '\t') {
			output[out_pos++] = ' ';
			continue;
		}
		if (c == '\033') {
			in_escape = 1;
			continue;
		}
		if (in_escape) {
			if ((c >= 'A' && c <= 'Z') ||
				(c >= 'a' && c <= 'z')) {
				in_escape = 0;
			}
			continue;
		}
		output[out_pos++] = c;
	}
	output[out_pos] = '\0';
	if (out_pos != len && debug) {
		wc_output_log_message("DEBUG",
			"Sanitized response: removed %zu problematic characters",
			len - out_pos);
	}
	return output;
}

int wc_execute_lookup(const Config* config,
		const char* query,
		const char* server_host,
		int port,
		wc_net_context_t* net_ctx,
		struct wc_result* out_res) {
	if (!out_res || !query || !config)
		return -1;
	struct wc_query q = { .raw = query, .start_server = server_host, .port = port };
	struct wc_lookup_opts lopts = { .max_hops = config->max_redirects,
		.no_redirect = config->no_redirect,
		.timeout_sec = config->timeout_sec,
		.retries = config->max_retries,
		.net_ctx = net_ctx ? net_ctx : wc_net_context_get_active(),
		.config = config };
	memset(out_res, 0, sizeof(*out_res));
	return wc_lookup_execute(&q, &lopts, out_res);
}

int wc_handle_suspicious_query(const char* query, int in_batch,
		const wc_selftest_injection_t* injection) {
	const char* safe_query = query ? query : "";
	if (!injection)
		injection = wc_query_exec_resolve_injection(
			wc_net_context_get_active());
	int forced = injection &&
		wc_query_exec_match_forced(injection->force_suspicious, safe_query);
	if (!forced) {
		if (!detect_suspicious_query(safe_query))
			return 0;
	} else {
		fprintf(stderr,
			"[SELFTEST] action=force-suspicious query=%s\n",
			safe_query);
		log_security_event(SEC_EVENT_SUSPICIOUS_QUERY,
			"Forced suspicious query via selftest: %s",
			safe_query);
	}
	if (in_batch) {
		log_security_event(SEC_EVENT_SUSPICIOUS_QUERY,
			"Blocked suspicious query in batch mode: %s",
			safe_query);
		fprintf(stderr,
			"Error: Suspicious query detected in batch mode: %s\n",
			safe_query);
		return 1;
	}
	log_security_event(SEC_EVENT_SUSPICIOUS_QUERY,
		"Blocked suspicious query: %s", safe_query);
	fprintf(stderr, "Error: Suspicious query detected\n");
	wc_cache_cleanup();
	return 1;
}

int wc_handle_private_ip(const Config* config,
		const char* query,
		const char* ip,
		int in_batch,
		const wc_selftest_injection_t* injection) {
	(void)in_batch;
	const Config* cfg = config;
	const char* safe_query = query ? query : "";
	if (!injection)
		injection = wc_query_exec_resolve_injection(
			wc_net_context_get_active());
	int forced = injection &&
		wc_query_exec_match_forced(injection->force_private, safe_query);
	if (!forced && !wc_client_is_private_ip(safe_query))
		return 0;
	if (forced) {
		fprintf(stderr,
			"[SELFTEST] action=force-private query=%s\n",
			safe_query);
	}
	const char* display_ip = (ip && *ip) ? ip : safe_query;
	int fold_output = cfg && cfg->fold_output;
	int plain_mode = cfg && cfg->plain_mode;
	const char* fold_sep = (cfg && cfg->fold_sep) ? cfg->fold_sep : " ";
	int fold_upper = cfg ? cfg->fold_upper : 0;
	if (fold_output) {
		char* folded = wc_fold_build_line(
			"", safe_query, "unknown",
			fold_sep,
			fold_upper);
		printf("%s", folded);
		free(folded);
	} else {
		if (!plain_mode) {
			wc_output_header_plain(safe_query);
		}
		printf("%s is a private IP address\n", display_ip);
		if (!plain_mode) {
			wc_output_tail_unknown_plain();
		}
	}
	return 1;
}

void wc_report_query_failure(const Config* config,
	const char* query,
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

	int fold_output = config && config->fold_output;
	int plain_mode = config && config->plain_mode;
	if (!fold_output && !plain_mode && res) {
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

char* wc_apply_response_filters(const Config* config,
		const char* query,
		const char* raw_response,
		int in_batch,
		wc_workbuf_t* wb) {
	(void)query;
	int debug = config && config->debug;
	if (!raw_response || !wb)
		return NULL;
	char* result = wc_workbuf_copy_cstr(wb, raw_response, __func__);
	result = normalize_line_endings_inplace(result);

	if (wc_title_is_enabled()) {
		if (debug) {
			fprintf(stderr,
				in_batch ? "[TRACE][batch] stage=title_filter in\n"
						: "[TRACE] stage=title_filter in\n");
		}
		result = wc_title_filter_response_wb(result, wb);
		if (debug) {
			fprintf(stderr,
				in_batch ? "[TRACE][batch] stage=title_filter out ptr=%p\n"
						: "[TRACE] stage=title_filter out ptr=%p\n",
				(void*)result);
		}
	}

	if (wc_grep_is_enabled()) {
		if (debug) {
			fprintf(stderr,
				in_batch ? "[TRACE][batch] stage=grep_filter in\n"
						: "[TRACE] stage=grep_filter in\n");
		}
		result = wc_grep_filter_wb(result, wb);
		if (debug) {
			fprintf(stderr,
				in_batch ? "[TRACE][batch] stage=grep_filter out ptr=%p\n"
						: "[TRACE] stage=grep_filter out ptr=%p\n",
				(void*)result);
		}
	}

	if (debug) {
		fprintf(stderr,
			in_batch ? "[TRACE][batch] stage=sanitize in ptr=%p\n"
					: "[TRACE] stage=sanitize in ptr=%p\n",
			(void*)result);
	}
	result = sanitize_response_for_output_wb(config, result, wb);
	if (debug && result) {
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
int wc_client_run_single_query(const Config* config,
		const wc_client_render_opts_t* render_opts_override,
		const char* query,
		const char* server_host,
		int port,
		wc_net_context_t* net_ctx) {
	const Config* cfg = config;
	wc_client_render_opts_t render_opts_local =
		wc_client_render_opts_init(cfg);
	const wc_client_render_opts_t* render_opts =
		render_opts_override ? render_opts_override : &render_opts_local;
	const wc_selftest_injection_t* injection =
		wc_query_exec_resolve_injection(net_ctx);
	int debug = render_opts->debug;
#ifdef WC_WORKBUF_ENABLE_STATS
	wc_workbuf_stats_reset();
#endif
	if (wc_signal_should_terminate()) {
		wc_signal_handle_pending_shutdown();
		return WC_EXIT_SIGINT;
	}
	// Security: detect suspicious queries
	if (wc_handle_suspicious_query(query, 0, injection))
		return 1;
	if (wc_handle_private_ip(cfg, query, query, 0, injection))
		return 0;

	struct wc_result res;
	int lrc = wc_execute_lookup(cfg, query, server_host, port, net_ctx, &res);
	int rc = 1;
	if (wc_signal_should_terminate()) {
		wc_signal_handle_pending_shutdown();
		wc_lookup_result_free(&res);
		return WC_EXIT_SIGINT;
	}

	if (debug)
		printf("[DEBUG] ===== MAIN QUERY START (lookup) =====\n");
	if (!lrc && res.body) {
		wc_client_render_single_success(cfg, render_opts,
			query, server_host, &res);
		rc = 0;
	} else {
		wc_report_query_failure(cfg, query, server_host,
			res.meta.last_connect_errno);
		wc_cache_cleanup();
	}
	wc_lookup_result_free(&res);
	wc_runtime_housekeeping_tick();

#ifdef WC_WORKBUF_ENABLE_STATS
	if (debug) {
		wc_workbuf_stats_t st = wc_workbuf_stats_snapshot();
		fprintf(stderr,
			"[WORKBUF-STATS] action=query reserves=%zu grow=%zu max_request=%zu max_cap=%zu max_view=%zu\n",
			st.reserves, st.grow_events, st.max_request, st.max_cap, st.max_view_size);
	}
#endif
	if (wc_signal_should_terminate()) {
		wc_signal_handle_pending_shutdown();
		return WC_EXIT_SIGINT;
	}
	return rc;
}
