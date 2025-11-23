// whois client (version 3.2.9) - migrated from lzispro
// License: GPL-3.0-or-later

// ============================================================================
// 1. Feature toggles and includes
// ============================================================================

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <regex.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "wc/wc_cache.h"
#include "wc/wc_client_meta.h"
#include "wc/wc_client_net.h"
#include "wc/wc_client_transport.h"
#include "wc/wc_client_util.h"
#include "wc/wc_config.h"
#include "wc/wc_defaults.h"
#include "wc/wc_dns.h"
#include "wc/wc_fold.h"
#include "wc/wc_grep.h"
#include "wc/wc_lookup.h"
#include "wc/wc_meta.h"
#include "wc/wc_net.h"
#include "wc/wc_opts.h"
#include "wc/wc_output.h"
#include "wc/wc_protocol_safety.h"
#include "wc/wc_query_exec.h"
#include "wc/wc_redirect.h"
#include "wc/wc_runtime.h"
#include "wc/wc_seclog.h"
#include "wc/wc_selftest.h"
#include "wc/wc_signal.h"
#include "wc/wc_title.h"
#include "wc/wc_util.h"

// Provide a portable replacement for strdup for strict C11 builds on CI while
// keeping call sites unchanged and enforcing fatal-on-OOM semantics.
#undef strdup
#define strdup(s) wc_safe_strdup((s), "strdup")

// ============================================================================
// 2. Defaults and shared constants
// ============================================================================

#define DEFAULT_WHOIS_PORT WC_DEFAULT_WHOIS_PORT
#define BUFFER_SIZE WC_DEFAULT_BUFFER_SIZE
#define MAX_RETRIES WC_DEFAULT_MAX_RETRIES
#define TIMEOUT_SEC WC_DEFAULT_TIMEOUT_SEC
#define DNS_CACHE_SIZE WC_DEFAULT_DNS_CACHE_SIZE
#define CONNECTION_CACHE_SIZE WC_DEFAULT_CONNECTION_CACHE_SIZE
#define CACHE_TIMEOUT WC_DEFAULT_CACHE_TIMEOUT
#define DEBUG WC_DEFAULT_DEBUG_LEVEL
#define MAX_REDIRECTS WC_DEFAULT_MAX_REDIRECTS

#define RESPONSE_SEPARATOR "\n=== %s query to %s ===\n"
#define FINAL_QUERY_TEXT "Final"
#define REDIRECTED_QUERY_TEXT "Redirected"
#define ADDITIONAL_QUERY_TEXT "Additional"

#define PROTOCOL_TIMEOUT_EXTENDED 30 // Extended timeout for large responses

// ============================================================================
// 3. Global configuration and debug helpers
// ============================================================================

Config g_config = {
	.whois_port = DEFAULT_WHOIS_PORT,
	.buffer_size = BUFFER_SIZE,
	.max_retries = MAX_RETRIES,
	.timeout_sec = TIMEOUT_SEC,
	.retry_interval_ms = 300,
	.retry_jitter_ms = 300,
	.dns_cache_size = DNS_CACHE_SIZE,
	.connection_cache_size = CONNECTION_CACHE_SIZE,
	.cache_timeout = CACHE_TIMEOUT,
	.debug = DEBUG,
	.max_redirects = MAX_REDIRECTS,
	.no_redirect = 0,
	.plain_mode = 0,
	.fold_output = 0,
	.fold_sep = NULL,
	.fold_upper = 1,
	.security_logging = 0,
	.fold_unique = 0,
};

int wc_is_debug_enabled(void) { return g_config.debug; }

// ============================================================================
// 4. Forward declarations
// ============================================================================

static char* perform_whois_query(const char* target, int port, const char* query,
	char** authoritative_server_out, char** first_server_host_out,
	char** first_server_ip_out);

// Keep legacy helpers referenced so -Wunused-function stays quiet while the
// new core modules gradually absorb the remaining logic.
static void wc_reference_legacy_helpers(void) {
	(void)&perform_whois_query;
}

// ============================================================================
// 5. Networking helpers
// ============================================================================

// ============================================================================
// 6. WHOIS execution helpers
// ============================================================================

static char* perform_whois_query(const char* target, int port, const char* query,
	char** authoritative_server_out, char** first_server_host_out,
	char** first_server_ip_out) {
	if (authoritative_server_out) *authoritative_server_out = NULL;
	if (first_server_host_out) *first_server_host_out = NULL;
	if (first_server_ip_out) *first_server_ip_out = NULL;
	int redirect_count = 0;
	char* current_target = strdup(target);
	int current_port = port;
	char* current_query = strdup(query);
	char* combined_result = NULL;
	const char* redirect_server = NULL;
	// Track visited redirect targets to avoid loops
	char* visited[16] = {0};
	char* final_authoritative = NULL;
	int literal_retry_performed = 0;
	char* first_server_host = NULL;
	char* first_server_ip = NULL;
	int first_connection_recorded = 0;

	if (!current_target || !current_query) {
		wc_output_log_message("ERROR", "Memory allocation failed for query parameters");
		free(current_target);
		free(current_query);
		return NULL;
	}

	wc_output_log_message("DEBUG", "Starting WHOIS query to %s:%d for %s", current_target,
		current_port, current_query);

	while (redirect_count <= g_config.max_redirects) {
		wc_output_log_message("DEBUG", "===== QUERY ATTEMPT %d =====", redirect_count + 1);
		wc_output_log_message("DEBUG", "Current target: %s, Query: %s", current_target, current_query);

		// Execute query
		int sockfd = -1;
		int retry_count = 0;
		char* result = NULL;

		// Retry mechanism with exponential backoff and fast failure
		while (retry_count < g_config.max_retries) {
			wc_output_log_message("DEBUG", "Query attempt %d/%d to %s", retry_count + 1, g_config.max_retries, current_target);

			// Check if server is backed off before attempting connection
			if (wc_cache_is_server_backed_off(current_target)) {
				wc_output_log_message("DEBUG", "Skipping backed off server: %s", current_target);
				break;
			}

			if (wc_client_connect_with_fallback(current_target, current_port, &sockfd) == 0) {
				if (!first_connection_recorded) {
					first_server_host = current_target ? strdup(current_target) : NULL;
					struct sockaddr_storage peer_addr;
					socklen_t peer_len = sizeof(peer_addr);
					if (getpeername(sockfd, (struct sockaddr*)&peer_addr, &peer_len) == 0) {
						char ipbuf[NI_MAXHOST];
						if (getnameinfo((struct sockaddr*)&peer_addr, peer_len, ipbuf, sizeof(ipbuf), NULL, 0, NI_NUMERICHOST) == 0) {
							first_server_ip = strdup(ipbuf);
						}
					}
					first_connection_recorded = 1;
				}
				// Register active connection for signal handling
				wc_signal_register_active_connection(current_target, current_port, sockfd);
				if (wc_client_send_query(sockfd, current_query) > 0) {
					result = wc_client_receive_response(sockfd);
					// Close and unregister connection
					wc_net_close_and_unregister(&sockfd);
					// Mark success on successful query
					wc_cache_mark_server_success(current_target);
					break;
				}
				wc_net_close_and_unregister(&sockfd);
			} else if (!literal_retry_performed && redirect_count == 0 &&
				wc_client_is_valid_ip_address(current_target)) {
				literal_retry_performed = 1;
				char* canonical = wc_dns_rir_fallback_from_ip(current_target);
				if (!canonical) {
					fprintf(stderr, "Error: Specified RIR server IP '%s' does not belong to any known RIR (PTR lookup failed).\n", current_target);
					if (first_server_host) free(first_server_host);
					if (first_server_ip) free(first_server_ip);
					free(current_target);
					free(current_query);
					if (combined_result) free(combined_result);
					return NULL;
				}
				if (g_config.debug) {
					wc_output_log_message("DEBUG", "IP literal %s mapped to RIR hostname %s", current_target, canonical);
				}
				fprintf(stderr, "Notice: Falling back to RIR hostname %s derived from %s\n", canonical, current_target);
				free(current_target);
				current_target = canonical;
				current_port = port;
				retry_count = 0;
				continue;
			}

			// Mark failure and calculate exponential backoff delay
			wc_cache_mark_server_failure(current_target);
			retry_count++;
			
			// Exponential backoff with jitter
			int base_delay = g_config.retry_interval_ms;
			int max_delay = 10000; // 10 seconds maximum delay
			int delay_ms = base_delay * (1 << retry_count); // Exponential backoff: base * 2^retry_count
			
			// Cap the delay at maximum
			if (delay_ms > max_delay) delay_ms = max_delay;
			
			// Add random jitter
			if (g_config.retry_jitter_ms > 0) {
				int j = rand() % (g_config.retry_jitter_ms + 1);
				delay_ms += j;
			}
			
			if (g_config.debug) {
				wc_output_log_message("DEBUG", "Retry %d/%d: waiting %d ms before next attempt", 
					   retry_count, g_config.max_retries, delay_ms);
			}
			
			if (delay_ms > 0) {
				struct timespec ts; ts.tv_sec = (time_t)(delay_ms/1000); ts.tv_nsec = (long)((delay_ms%1000)*1000000L);
				nanosleep(&ts, NULL);
			}
		}

		if (result == NULL) {
			// Check if failure was due to signal interruption
			if (wc_signal_should_terminate()) {
				wc_output_log_message("INFO", "Query interrupted by user signal");
				if (first_server_host) free(first_server_host);
				if (first_server_ip) free(first_server_ip);
				free(current_target);
				free(current_query);
				if (combined_result) free(combined_result);
				return NULL;
			}
			
			wc_output_log_message("DEBUG", "Query failed to %s after %d attempts", current_target, g_config.max_retries);

			// If this is the first query, return error
			if (redirect_count == 0) {
				if (first_server_host) free(first_server_host);
				if (first_server_ip) free(first_server_ip);
				free(current_target);
				free(current_query);
				if (combined_result) free(combined_result);
				return NULL;
			}

			// If not the first, return collected results
			if (!final_authoritative && current_target) {
				// best-effort authoritative guess
				final_authoritative = strdup(current_target);
			}
			break;
		}

		// Protocol injection detection
		if (wc_protocol_detect_injection(current_query, result)) {
			log_security_event(SEC_EVENT_RESPONSE_TAMPERING, 
						  "Protocol injection detected for query: %s", current_query);
			// Continue processing but log the security event
		}

		// Check if redirect is needed
		if (!g_config.no_redirect && needs_redirect(result)) {
            wc_output_log_message("DEBUG", "==== REDIRECT REQUIRED ====");
			int force_iana = 0;
			if (current_target && strcasecmp(current_target, "whois.iana.org") != 0) {
				int visited_iana = 0;
				for (int vi = 0; vi < 16 && visited[vi]; vi++) {
					if (strcasecmp(visited[vi], "whois.iana.org") == 0) {
						visited_iana = 1;
						break;
					}
				}
				if (!visited_iana) {
					force_iana = 1;
				}
			}
			if (force_iana) {
				redirect_server = strdup("whois.iana.org");
				if (redirect_server == NULL) {
					wc_output_log_message("ERROR", "Failed to allocate redirect server string");
				}
				wc_output_log_message("DEBUG", "Forcing redirect via IANA for %s", current_target);
			} else {
				redirect_server = extract_refer_server(result);
			}

			if (redirect_server) {
				wc_output_log_message("DEBUG", "Redirecting to: %s", redirect_server);

				// Check if redirecting to same server
				if (strcmp(redirect_server, current_target) == 0) {
					wc_output_log_message("DEBUG", "Redirect server same as current target, stopping redirect");
					free((void*)redirect_server);
					redirect_server = NULL;

					// Add current result to final result
					if (combined_result == NULL) {
						combined_result = result;
					} else {
						size_t new_len = strlen(combined_result) + strlen(result) + 100;
						char* new_combined = malloc(new_len);
						if (new_combined) {
							snprintf(new_combined, new_len,
									 "%s\n=== Additional query to %s ===\n%s",
									 combined_result, current_target, result);
							free(combined_result);
							free(result);
							combined_result = new_combined;
						} else {
							free(result);
						}
					}
					if (!final_authoritative && current_target)
						final_authoritative = strdup(current_target);
					break;
				}

				// Save current result
				if (combined_result == NULL) {
					combined_result = result;
				} else {
					size_t new_len = strlen(combined_result) + strlen(result) + 100;
					char* new_combined = malloc(new_len);
					if (new_combined) {
						snprintf(new_combined, new_len,
								 "%s\n=== Redirected query to %s ===\n%s",
								 combined_result, current_target, result);
						free(combined_result);
						free(result);
						combined_result = new_combined;
					} else {
						free(result);  // Ensure memory is freed
					}
				}

				// Prepare for next query with loop guard
				free(current_target);
				int loop = 0;
				// simple visited check to avoid A<->B loops
				// note: visited list declared at function top
				for (int i = 0; i < 16 && visited[i]; i++) {
					if (strcmp(visited[i], redirect_server) == 0) { loop = 1; break; }
				}
				// record visited if room
				if (!loop) {
					for (int i = 0; i < 16; i++) {
						if (!visited[i]) { visited[i] = strdup(redirect_server); break; }
					}
				}
				current_target = strdup(redirect_server);
				free((void*)redirect_server);
				redirect_server = NULL;

				if (!current_target) {
					wc_output_log_message("DEBUG", "Memory allocation failed for redirect target");
					break;
				}
				if (loop) {
					wc_output_log_message("WARN", "Detected redirect loop, stop following redirects");
					if (!final_authoritative && current_target)
						final_authoritative = strdup(current_target);
					break;
				}

				redirect_count++;
				continue;
			} else {
				wc_output_log_message("DEBUG", "No redirect server found, stopping redirect");
				if (combined_result == NULL) {
					combined_result = result;
				} else {
					size_t new_len = strlen(combined_result) + strlen(result) + 100;
					char* new_combined = malloc(new_len);
					if (new_combined) {
						snprintf(new_combined, new_len,
								 "%s\n=== Final query to %s ===\n%s",
								 combined_result, current_target, result);
						free(combined_result);
						free(result);
						combined_result = new_combined;
					} else {
						free(result);
					}
				}
				break;
			}
		} else {
			wc_output_log_message("DEBUG", "No redirect needed, returning result");
			if (combined_result == NULL) {
				combined_result = result;
			} else {
				size_t new_len = strlen(combined_result) + strlen(result) + 100;
				char* new_combined = malloc(new_len);
				if (new_combined) {
					snprintf(new_combined, new_len,
							 "%s\n=== Final query to %s ===\n%s",
							 combined_result, current_target, result);
					free(combined_result);
					free(result);
					combined_result = new_combined;
				} else {
					free(result);
				}
			}
			if (!final_authoritative && current_target)
				final_authoritative = strdup(current_target);
			break;
		}
	}

	if (redirect_count > g_config.max_redirects) {
		wc_output_log_message("DEBUG", "Maximum redirects reached (%d)", g_config.max_redirects);

		// Add warning message
		if (combined_result) {
			size_t new_len = strlen(combined_result) + 200;
			char* new_result = malloc(new_len);
			if (new_result) {
				snprintf(new_result, new_len,
						 "Warning: Maximum redirects reached (%d).\n"
						 "You may need to manually query the final server for "
						 "complete information.\n\n%s",
						 g_config.max_redirects, combined_result);
				free(combined_result);
				combined_result = new_result;
			}
		}
	}

	// Cleanup resources
	if (redirect_server) free((void*)redirect_server);
	// free visited records
	for (int i = 0; i < 16; i++) { if (visited[i]) free(visited[i]); }
	// Preserve authoritative if not set
	if (!final_authoritative && current_target)
		final_authoritative = strdup(current_target);
	free(current_target);
	free(current_query);
	if (first_server_host_out && first_server_host) {
		*first_server_host_out = first_server_host;
		first_server_host = NULL;
	}
	if (first_server_ip_out && first_server_ip) {
		*first_server_ip_out = first_server_ip;
		first_server_ip = NULL;
	}
	if (!first_server_host_out && first_server_host) free(first_server_host);
	if (!first_server_ip_out && first_server_ip) free(first_server_ip);
	
	// Perform cache maintenance after query completion
	wc_cache_cleanup_expired_entries();
	if (g_config.debug) {
		wc_cache_validate_integrity();
	}
	
	if (authoritative_server_out) *authoritative_server_out = final_authoritative;
	else if (final_authoritative) free(final_authoritative);
	return combined_result;
}

// ============================================================================
// 11. Implementation of the main entry function
// ============================================================================

// Helpers for lookup/response handling are implemented in
// src/core/whois_query_exec.c

// Meta/display handling has been moved to src/core/client_meta.c

int main(int argc, char* argv[]) {
	// Reference legacy helpers so compilers keep them available until the
	// new query exec module fully replaces the old flow.
	wc_reference_legacy_helpers();
	// Parse options via wc_opts module
	wc_opts_t opts;
	if (wc_opts_parse(argc, argv, &opts) != 0) {
		// CLI usage/parameter error: keep returning 1 via
		// WC_EXIT_FAILURE for now, but route through a helper to
		// make the intent explicit.
		return wc_client_exit_usage_error(argv[0], &g_config);
	}

    // Runtime initialization and atexit registration that depend only
	// on parsed options but not yet on derived config.
	wc_runtime_init(&opts);

	// Map parsed options back to legacy global config (incremental migration)
	wc_client_apply_opts_to_config(&opts, &g_config);

	// Apply fold unique behavior
	extern void wc_fold_set_unique(int on);
	wc_fold_set_unique(g_config.fold_unique);

	// Ensure fold separator default if still unset
	if (!g_config.fold_sep) g_config.fold_sep = strdup(" ");

	// Configure security logging module according to parsed options (already set in parse)
	wc_seclog_set_enabled(g_config.security_logging);

	// Language option removed; always use English outputs

	// Validate configuration
	if (!wc_config_validate(&g_config)) return WC_EXIT_FAILURE;

#ifdef WHOIS_SECLOG_TEST
	// Run optional security log self-test if enabled via environment
	maybe_run_seclog_self_test();
#endif

#ifdef WHOIS_GREP_TEST
	// Optional grep self-test driven by env var
	maybe_run_grep_self_test();
#endif

	// Check if cache sizes are reasonable
	if (!wc_cache_validate_sizes()) {
		fprintf(stderr, "Error: Invalid cache sizes, using defaults\n");
		g_config.dns_cache_size = DNS_CACHE_SIZE;
		g_config.connection_cache_size = CONNECTION_CACHE_SIZE;
	}

	if (g_config.debug) printf("[DEBUG] Parsed command line arguments\n");
	if (g_config.debug) {
		printf("[DEBUG] Final configuration:\n");
		printf("        Buffer size: %zu bytes\n", g_config.buffer_size);
		printf("        DNS cache size: %zu entries\n",
			   g_config.dns_cache_size);
		printf("        Connection cache size: %zu entries\n",
			   g_config.connection_cache_size);
		printf("        Timeout: %d seconds\n", g_config.timeout_sec);
		printf("        Max retries: %d\n", g_config.max_retries);
		printf("        Retry interval: %d ms\n", g_config.retry_interval_ms);
		printf("        Retry jitter: %d ms\n", g_config.retry_jitter_ms);
		printf("        DNS retry: %d (interval %d ms, addrconfig %s, max candidates %d)\n",
			g_config.dns_retry, g_config.dns_retry_interval_ms, g_config.dns_addrconfig?"on":"off", g_config.dns_max_candidates);
	}

	// 2. Delegate remaining logic (meta handling, mode detection,
	// resource initialization and single vs batch dispatch) to the
	// core orchestrator.
	int rc = wc_client_run_with_mode(&opts, argc, argv, &g_config);
	wc_opts_free(&opts);
	return rc;
}

