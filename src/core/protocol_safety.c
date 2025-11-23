// SPDX-License-Identifier: GPL-3.0-or-later
// WHOIS protocol safety helpers implementation.

#include "wc/wc_protocol_safety.h"

#include <stdio.h>
#include <string.h>

#include "wc/wc_output.h"
#include "wc/wc_seclog.h"

enum {
	WC_PROTOCOL_MIN_RESPONSE_SIZE = 10,
	WC_PROTOCOL_MAX_RESPONSE_SIZE = 10 * 1024 * 1024,
	WC_PROTOCOL_MAX_LINE_LENGTH = 1024,
	WC_PROTOCOL_MAX_LINES = 10000,
};

static int protocol_is_safe_character(unsigned char c)
{
	if (c >= 32 && c <= 126) {
		return 1;
	}
	if (c == '\t' || c == '\n' || c == '\r') {
		return 1;
	}
	return 0;
}

int wc_protocol_validate_response_data(const char* data, size_t len)
{
	if (!data || len == 0) {
		log_message("WARN", "Response data is NULL or empty");
		return 0;
	}

	int line_length = 0;
	const int max_line_length = 1024;

	for (size_t i = 0; i < len; i++) {
		unsigned char c = (unsigned char)data[i];

		if (c == 0) {
			log_message("WARN", "Response contains null byte at position %zu", i);
			return 0;
		}

		if (c < 32 && c != '\n' && c != '\r' && c != '\t') {
			log_message("WARN", "Response contains invalid control character 0x%02x at position %zu", c, i);
			return 0;
		}

		if (c == '\n') {
			line_length = 0;
		} else {
			line_length++;
			if (line_length > max_line_length) {
				log_message("WARN", "Response line too long (%d characters), possible data corruption", line_length);
				return 0;
			}
		}
	}

	return 1;
}

int wc_protocol_validate_whois_response(const char* response, size_t len)
{
	if (!response || len == 0) {
		log_message("WARN", "Empty or NULL WHOIS protocol response");
		return 0;
	}

	if (len < WC_PROTOCOL_MIN_RESPONSE_SIZE) {
		log_message("WARN", "WHOIS response too short: %zu bytes", len);
		return 0;
	}

	if (len > WC_PROTOCOL_MAX_RESPONSE_SIZE) {
		log_message("WARN", "WHOIS response too large: %zu bytes", len);
		return 0;
	}

	int has_valid_content = 0;
	int line_count = 0;
	const char* ptr = response;

	while (*ptr && line_count < WC_PROTOCOL_MAX_LINES) {
		const char* line_start = ptr;
		size_t line_len = 0;

		while (*ptr && *ptr != '\n' && *ptr != '\r') {
			if (!protocol_is_safe_character((unsigned char)*ptr)) {
				log_message("WARN", "Unsafe character in WHOIS response: 0x%02x", (unsigned char)*ptr);
				return 0;
			}
			ptr++;
			line_len++;
		}

		if (line_len > WC_PROTOCOL_MAX_LINE_LENGTH) {
			log_message("WARN", "WHOIS response line too long: %zu characters", line_len);
			return 0;
		}

		if (line_len > 0) {
			if (line_start[0] != '%' && line_start[0] != '#') {
				for (size_t i = 0; i < line_len; i++) {
					if (line_start[i] == ':') {
						has_valid_content = 1;
						break;
					}
				}
			}
		}

		line_count++;

		while (*ptr == '\n' || *ptr == '\r') {
			ptr++;
		}
	}

	if (!has_valid_content) {
		int has_printable = 0;
		for (const char* p = response; *p; p++) {
			unsigned char c = (unsigned char)*p;
			if (c > ' ' && c < 0x7f) {
				has_printable = 1;
				break;
			}
		}
		if (!has_printable) {
			log_message("WARN", "WHOIS response lacks valid content structure");
			return 0;
		}
		log_message("INFO", "WHOIS response lacks key/value pairs, continuing for redirect compatibility");
	}

	return 1;
}

int wc_protocol_check_response_integrity(const char* response, size_t len)
{
	if (!response || len == 0) {
		return 0;
	}

	for (size_t i = 0; i < len; i++) {
		if (response[i] == 0 && i < len - 1) {
			log_security_event(SEC_EVENT_RESPONSE_TAMPERING,
			                  "Null byte detected in WHOIS response at position %zu", i);
			return 0;
		}
	}

	int has_crlf = 0;
	int has_lf = 0;

	for (size_t i = 0; i < len - 1; i++) {
		if (response[i] == '\r' && response[i + 1] == '\n') {
			has_crlf = 1;
		} else if (response[i] == '\n' && (i == 0 || response[i - 1] != '\r')) {
			has_lf = 1;
		}
	}

	if (has_crlf && has_lf) {
		log_message("WARN", "Mixed line endings in WHOIS response (possible tampering)");
		return 0;
	}

	return 1;
}

int wc_protocol_detect_anomalies(const char* response)
{
	if (!response) return 0;

	int anomalies = 0;

	const char* suspicious_patterns[] = {
		"<script>",
		"javascript:",
		"vbscript:",
		"onload=",
		"onerror=",
		"eval(",
		"document.cookie",
		"window.location",
		"base64,",
		"data:text/html",
		NULL
	};

	for (int i = 0; suspicious_patterns[i] != NULL; i++) {
		if (strstr(response, suspicious_patterns[i])) {
			log_security_event(SEC_EVENT_RESPONSE_TAMPERING,
			                  "Detected suspicious pattern in WHOIS response: %s",
			                  suspicious_patterns[i]);
			anomalies++;
		}
	}

	int redirect_count = 0;
	const char* ptr = response;
	while ((ptr = strstr(ptr, "refer:")) != NULL) {
		redirect_count++;
		ptr += 6;

		if (redirect_count > 5) {
			log_security_event(SEC_EVENT_RESPONSE_TAMPERING,
			                  "Excessive redirect references in response: %d",
			                  redirect_count);
			anomalies++;
			break;
		}
	}

	for (const char* p = response; *p; p++) {
		unsigned char c = (unsigned char)*p;
		if (c < 32 && c != '\n' && c != '\r' && c != '\t') {
			if (c != 0) {
				log_security_event(SEC_EVENT_RESPONSE_TAMPERING,
				                  "Binary/control character in WHOIS response: 0x%02x", c);
				anomalies++;
				break;
			}
		}
	}

	return anomalies;
}

int wc_protocol_detect_injection(const char* query, const char* response)
{
	if (!query || !response) {
		return 0;
	}

	int injection_detected = 0;

	if (strstr(response, query)) {
		const char* suspicious_contexts[] = {
			"Error:",
			"Warning:",
			"Invalid",
			"Unknown",
			"not found",
			"no match",
			NULL
		};

		for (int i = 0; suspicious_contexts[i] != NULL; i++) {
			const char* ctx_pos = strstr(response, suspicious_contexts[i]);
			const char* query_pos = strstr(response, query);

			if (ctx_pos && query_pos && query_pos > ctx_pos &&
			    (query_pos - ctx_pos) < 100) {
				char pattern[256];
				snprintf(pattern, sizeof(pattern), "%s.*%s", suspicious_contexts[i], query);

				log_security_event(SEC_EVENT_RESPONSE_TAMPERING,
				                  "Possible query injection detected: %s in %s context",
				                  query, suspicious_contexts[i]);
				injection_detected = 1;
				break;
			}
		}
	}

	return injection_detected;
}
