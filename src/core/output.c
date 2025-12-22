// SPDX-License-Identifier: GPL-3.0-or-later
// Output helpers for WHOIS client: headers/tails formatting and logging.

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "wc/wc_output.h"
#include "wc/wc_runtime.h"

static int wc_output_debug_enabled(void)
{
	const wc_runtime_cfg_view_t* view = wc_runtime_config_view();
	return view ? view->debug : 0;
}

void wc_output_header_plain(const char* query)
{
	printf("=== Query: %s ===\n", query);
}

void wc_output_header_via_ip(const char* query,
	const char* via_host,
	const char* via_ip)
{
	printf("=== Query: %s via %s @ %s ===\n", query, via_host, via_ip);
}

void wc_output_header_via_unknown(const char* query,
	const char* via_host)
{
	printf("=== Query: %s via %s @ unknown ===\n", query, via_host);
}

void wc_output_tail_unknown_plain(void)
{
	printf("=== Authoritative RIR: unknown ===\n");
}

void wc_output_tail_unknown_unknown(void)
{
	printf("=== Authoritative RIR: unknown @ unknown ===\n");
}

void wc_output_tail_authoritative_ip(const char* host,
	const char* ip)
{
	printf("=== Authoritative RIR: %s @ %s ===\n", host, ip);
}

void wc_output_log_message(const char* level, const char* format, ...)
{
	int always = 0;
	if (level) {
		if (strcmp(level, "ERROR") == 0 || strcmp(level, "WARN") == 0 ||
		    strcmp(level, "WARNING") == 0) {
			always = 1;
		}
	}

	if (!wc_output_debug_enabled() && !always) {
		return;
	}

	va_list args;
	va_start(args, format);

	time_t now = time(NULL);
	struct tm* t = localtime(&now);
	fprintf(stderr,
	        "[%04d-%02d-%02d %02d:%02d:%02d] [%s] ",
	        t ? t->tm_year + 1900 : 0,
	        t ? t->tm_mon + 1 : 0,
	        t ? t->tm_mday : 0,
	        t ? t->tm_hour : 0,
	        t ? t->tm_min : 0,
	        t ? t->tm_sec : 0,
	        level ? level : "LOG");

	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
	va_end(args);
}
