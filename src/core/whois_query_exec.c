// Single-query execution helpers. Title/grep/fold glue lives in pipeline.c
// via wc_pipeline_render.

#include <stdio.h>
#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#if defined(_WIN32) || defined(__MINGW32__)
#include <ws2tcpip.h>
#else
#include <netdb.h>
#endif
#include <time.h>

#include "wc/wc_query_exec.h"
#include "wc/wc_client_flow.h"
#include "wc/wc_client_util.h"
#include "wc/wc_debug.h"
#include "wc/wc_fold.h"
#include "wc/wc_lookup.h"
#include "wc/wc_net.h"
#include "wc/wc_output.h"
#include "wc/wc_pipeline.h"
#include "wc/wc_runtime.h"
#include "wc/wc_seclog.h"
#include "wc/wc_selftest.h"
#include "wc/wc_server.h"
#include "wc/wc_signal.h"
#include "wc/wc_util.h"
#include "wc/wc_cache.h"

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

static int wc_query_exec_now(struct timespec* ts)
{
	if (!ts)
		return -1;
#if defined(CLOCK_MONOTONIC)
	if (clock_gettime(CLOCK_MONOTONIC, ts) == 0)
		return 0;
	return -1;
#else
	struct timespec tmp;
	tmp.tv_sec = time(NULL);
	tmp.tv_nsec = 0;
	*ts = tmp;
	return 0;
#endif
}

static const char* wc_gai_strerror_fallback(int err)
{
#ifdef EAI_AGAIN
	if (err == EAI_AGAIN) return "temporary failure in name resolution";
#endif
#ifdef EAI_FAIL
	if (err == EAI_FAIL) return "non-recoverable name resolution failure";
#endif
#ifdef EAI_NONAME
	if (err == EAI_NONAME) return "name or service not known";
#endif
#ifdef EAI_NODATA
	if (err == EAI_NODATA) return "no address associated with name";
#endif
#ifdef EAI_SERVICE
	if (err == EAI_SERVICE) return "service not supported for socket type";
#endif
#ifdef EAI_MEMORY
	if (err == EAI_MEMORY) return "memory allocation failure";
#endif
#ifdef EAI_OVERFLOW
	if (err == EAI_OVERFLOW) return "argument buffer overflow";
#endif
	(void)err;
	return NULL;
}

static long long wc_query_exec_diff_ms(const struct timespec* start,
	const struct timespec* end)
{
	if (!start || !end)
		return 0;
	long long sec = (long long)(end->tv_sec - start->tv_sec);
	long long nsec = (long long)(end->tv_nsec - start->tv_nsec);
	if (nsec < 0) {
		nsec += 1000000000LL;
		sec -= 1;
	}
	if (sec < 0)
		return 0;
	return sec * 1000LL + (nsec / 1000000LL);
}

#ifndef SEC_EVENT_SUSPICIOUS_QUERY
#define SEC_EVENT_SUSPICIOUS_QUERY 2
#endif

static int detect_suspicious_query(const char* query)
{
	if (!query || !*query)
		return 0;
	const char* suspicious_patterns[] = {
		"..",
		";",
		"|",
		"&&",
		"||",
		"`",
		"$",
		"(",
		")",
		"\\n",
		"\\r",
		"\\0",
		"--",
		"/*",
		"*/",
		"<",
		">",
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

int wc_execute_lookup(const Config* config,
		const char* query,
		const char* server_host,
		int port,
		wc_net_context_t* net_ctx,
		struct wc_result* out_res)
{
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
		const wc_selftest_injection_t* injection)
{
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
		if (in_batch) {
			fprintf(stderr,
				"Error: Suspicious query detected in batch mode: %s\n",
				safe_query);
		} else {
			fprintf(stderr, "Error: Suspicious query detected\n");
		}
		return 0;
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
		const wc_selftest_injection_t* injection)
{
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
	fprintf(stderr, "Error: Private query denied\n");
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
	int err,
	const struct wc_result* res)
{
	int lerr = err;
	const char* host = NULL;
	const char* ip = NULL;
	if (res && res->meta.via_host[0])
		host = res->meta.via_host;
	else
		host = server_host ? server_host : "whois.iana.org";
	if (res && res->meta.via_ip[0])
		ip = res->meta.via_ip;
	else
		ip = "unknown";
	if (lerr) {
		const char* cause = NULL;
		int gai_mapped = 0;
#ifdef EAI_AGAIN
		if (lerr == EAI_AGAIN) gai_mapped = 1;
#endif
#ifdef EAI_FAIL
		if (lerr == EAI_FAIL) gai_mapped = 1;
#endif
#ifdef EAI_NONAME
		if (lerr == EAI_NONAME) gai_mapped = 1;
#endif
#ifdef EAI_NODATA
		if (lerr == EAI_NODATA) gai_mapped = 1;
#endif
#ifdef EAI_SERVICE
		if (lerr == EAI_SERVICE) gai_mapped = 1;
#endif
#ifdef EAI_MEMORY
		if (lerr == EAI_MEMORY) gai_mapped = 1;
#endif
#ifdef EAI_OVERFLOW
		if (lerr == EAI_OVERFLOW) gai_mapped = 1;
#endif
		if (gai_mapped) {
			cause = wc_gai_strerror_fallback(lerr);
		}
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
			if (!cause)
				cause = strerror(lerr);
			break;
		}
		fprintf(stderr,
			"Error: Query failed for %s (%s, errno=%d, host=%s, ip=%s)\n",
			query, cause, lerr, host, ip);
	} else {
		fprintf(stderr,
			"Error: Query failed for %s (errno=0, host=%s, ip=%s)\n",
			query, host, ip);
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

int wc_client_run_single_query(const Config* config,
		const wc_client_render_opts_t* render_opts_override,
		const char* query,
		const char* server_host,
		int port,
		wc_net_context_t* net_ctx)
{
	const Config* cfg = config;
	wc_client_render_opts_t render_opts_local =
		wc_client_render_opts_init(cfg);
	const wc_client_render_opts_t* render_opts =
		render_opts_override ? render_opts_override : &render_opts_local;
	const wc_selftest_injection_t* injection =
		wc_query_exec_resolve_injection(net_ctx);
	int debug = render_opts->debug;
	struct timespec t_lookup_start = {0}, t_lookup_end = {0};
	struct timespec t_render_start = {0}, t_render_end = {0};
	int timing_ok = 0;
#ifdef WC_WORKBUF_ENABLE_STATS
	wc_workbuf_stats_reset();
#endif
	if (wc_signal_should_terminate()) {
		wc_signal_handle_pending_shutdown();
		return WC_EXIT_SIGINT;
	}
	if (wc_handle_suspicious_query(query, 0, injection))
		return 1;
	if (wc_handle_private_ip(cfg, query, query, 0, injection))
		return 0;

	struct wc_result res;
	if (debug >= 2) {
		if (wc_query_exec_now(&t_lookup_start) == 0)
			timing_ok = 1;
	}
	int lrc = wc_execute_lookup(cfg, query, server_host, port, net_ctx, &res);
	if (debug >= 2 && timing_ok)
		(void)wc_query_exec_now(&t_lookup_end);
	int rc = 1;
	if (wc_signal_should_terminate()) {
		wc_signal_handle_pending_shutdown();
		wc_lookup_result_free(&res);
		return WC_EXIT_SIGINT;
	}

	if (debug)
		printf("[DEBUG] ===== MAIN QUERY START (lookup) =====\n");
	if (!lrc && res.body) {
		if (debug >= 2 && timing_ok)
			(void)wc_query_exec_now(&t_render_start);
		wc_pipeline_render(cfg, render_opts,
			query, server_host, &res, 0);
		if (debug >= 2 && timing_ok)
			(void)wc_query_exec_now(&t_render_end);
		rc = 0;
	} else {
		wc_report_query_failure(cfg, query, server_host,
			res.meta.last_connect_errno, &res);
		wc_cache_cleanup();
	}
	if (debug >= 2 && timing_ok) {
		long long lookup_ms = wc_query_exec_diff_ms(&t_lookup_start,
			&t_lookup_end);
		long long render_ms = 0;
		long long total_ms = lookup_ms;
		if (res.body) {
			render_ms = wc_query_exec_diff_ms(&t_render_start, &t_render_end);
			total_ms = wc_query_exec_diff_ms(&t_lookup_start, &t_render_end);
		}
		fprintf(stderr,
			"[SINGLE-PROFILE] query=%s lookup_ms=%lld render_ms=%lld total_ms=%lld hops=%d fallback_flags=0x%x errno=%d body_len=%zu\n",
			query,
			lookup_ms,
			render_ms,
			total_ms,
			res.meta.hops,
			res.meta.fallback_flags,
			res.meta.last_connect_errno,
			res.body_len);
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
