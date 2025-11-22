// SPDX-License-Identifier: GPL-3.0-or-later
// Output helpers for WHOIS client: headers/tails formatting.

#include <stdio.h>

#include "wc/wc_output.h"

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
