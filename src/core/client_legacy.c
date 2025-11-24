// SPDX-License-Identifier: GPL-3.0-or-later
// Legacy WHOIS query orchestration preserved for compatibility.

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "wc/wc_cache.h"
#include "wc/wc_client_legacy.h"
#include "wc/wc_client_net.h"
#include "wc/wc_client_transport.h"
#include "wc/wc_client_util.h"
#include "wc/wc_config.h"
#include "wc/wc_dns.h"
#include "wc/wc_net.h"
#include "wc/wc_output.h"
#include "wc/wc_protocol_safety.h"
#include "wc/wc_redirect.h"
#include "wc/wc_seclog.h"
#include "wc/wc_signal.h"
#include "wc/wc_util.h"

extern Config g_config;

char* wc_client_perform_legacy_query(const char* target,
                                     int port,
                                     const char* query,
                                     char** authoritative_server_out,
                                     char** first_server_host_out,
                                     char** first_server_ip_out)
{
    if (authoritative_server_out) *authoritative_server_out = NULL;
    if (first_server_host_out) *first_server_host_out = NULL;
    if (first_server_ip_out) *first_server_ip_out = NULL;

    int redirect_count = 0;
    char* current_target = target ? wc_safe_strdup(target, __func__) : NULL;
    int current_port = port;
    char* current_query = query ? wc_safe_strdup(query, __func__) : NULL;
    char* combined_result = NULL;
    char* redirect_server = NULL;
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

    wc_output_log_message("DEBUG",
                          "Starting WHOIS query to %s:%d for %s",
                          current_target,
                          current_port,
                          current_query);

    while (redirect_count <= g_config.max_redirects) {
        wc_output_log_message("DEBUG",
                              "===== QUERY ATTEMPT %d =====",
                              redirect_count + 1);
        wc_output_log_message("DEBUG",
                              "Current target: %s, Query: %s",
                              current_target,
                              current_query);

        int sockfd = -1;
        int retry_count = 0;
        char* result = NULL;

        while (retry_count < g_config.max_retries) {
            wc_output_log_message("DEBUG",
                                  "Query attempt %d/%d to %s",
                                  retry_count + 1,
                                  g_config.max_retries,
                                  current_target);

            if (wc_cache_is_server_backed_off(current_target)) {
                wc_output_log_message("DEBUG",
                                      "Skipping backed off server: %s",
                                      current_target);
                break;
            }

            if (wc_client_connect_with_fallback(current_target, current_port, &sockfd) == 0) {
                if (!first_connection_recorded) {
                    first_server_host = current_target ? wc_safe_strdup(current_target, __func__) : NULL;
                    struct sockaddr_storage peer_addr;
                    socklen_t peer_len = sizeof(peer_addr);
                    if (getpeername(sockfd, (struct sockaddr*)&peer_addr, &peer_len) == 0) {
                        char ipbuf[NI_MAXHOST];
                        if (getnameinfo((struct sockaddr*)&peer_addr,
                                        peer_len,
                                        ipbuf,
                                        sizeof(ipbuf),
                                        NULL,
                                        0,
                                        NI_NUMERICHOST) == 0) {
                            first_server_ip = wc_safe_strdup(ipbuf, __func__);
                        }
                    }
                    first_connection_recorded = 1;
                }

                wc_signal_register_active_connection(current_target, current_port, sockfd);
                if (wc_client_send_query(sockfd, current_query) > 0) {
                    result = wc_client_receive_response(sockfd);
                    wc_net_close_and_unregister(&sockfd);
                    wc_cache_mark_server_success(current_target);
                    break;
                }
                wc_net_close_and_unregister(&sockfd);
            } else if (!literal_retry_performed && redirect_count == 0 &&
                       wc_client_is_valid_ip_address(current_target)) {
                literal_retry_performed = 1;
                char* canonical = wc_dns_rir_fallback_from_ip(current_target);
                if (!canonical) {
                    fprintf(stderr,
                            "Error: Specified RIR server IP '%s' does not belong to any known RIR (PTR lookup failed).\n",
                            current_target);
                    free(first_server_host);
                    free(first_server_ip);
                    free(current_target);
                    free(current_query);
                    free(combined_result);
                    return NULL;
                }
                if (g_config.debug) {
                    wc_output_log_message("DEBUG",
                                           "IP literal %s mapped to RIR hostname %s",
                                           current_target,
                                           canonical);
                }
                fprintf(stderr,
                        "Notice: Falling back to RIR hostname %s derived from %s\n",
                        canonical,
                        current_target);
                free(current_target);
                current_target = canonical;
                current_port = port;
                retry_count = 0;
                continue;
            }

            wc_cache_mark_server_failure(current_target);
            retry_count++;

            int base_delay = g_config.retry_interval_ms;
            int max_delay = 10000;
            int delay_ms = base_delay * (1 << retry_count);
            if (delay_ms > max_delay) delay_ms = max_delay;
            if (g_config.retry_jitter_ms > 0) {
                int j = rand() % (g_config.retry_jitter_ms + 1);
                delay_ms += j;
            }

            if (g_config.debug) {
                wc_output_log_message("DEBUG",
                                       "Retry %d/%d: waiting %d ms before next attempt",
                                       retry_count,
                                       g_config.max_retries,
                                       delay_ms);
            }

            if (delay_ms > 0) {
                struct timespec ts;
                ts.tv_sec = (time_t)(delay_ms / 1000);
                ts.tv_nsec = (long)((delay_ms % 1000) * 1000000L);
                nanosleep(&ts, NULL);
            }
        }

        if (result == NULL) {
            if (wc_signal_should_terminate()) {
                wc_output_log_message("INFO", "Query interrupted by user signal");
                free(first_server_host);
                free(first_server_ip);
                free(current_target);
                free(current_query);
                free(combined_result);
                return NULL;
            }

            wc_output_log_message("DEBUG",
                                  "Query failed to %s after %d attempts",
                                  current_target,
                                  g_config.max_retries);

            if (redirect_count == 0) {
                free(first_server_host);
                free(first_server_ip);
                free(current_target);
                free(current_query);
                free(combined_result);
                return NULL;
            }

            if (!final_authoritative && current_target) {
                final_authoritative = wc_safe_strdup(current_target, __func__);
            }
            break;
        }

        if (wc_protocol_detect_injection(current_query, result)) {
            log_security_event(SEC_EVENT_RESPONSE_TAMPERING,
                               "Protocol injection detected for query: %s",
                               current_query);
        }

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
                redirect_server = wc_safe_strdup("whois.iana.org", __func__);
                if (!redirect_server) {
                    wc_output_log_message("ERROR", "Failed to allocate redirect server string");
                }
                wc_output_log_message("DEBUG",
                                       "Forcing redirect via IANA for %s",
                                       current_target);
            } else {
                char* extracted = extract_refer_server(result);
                if (extracted) {
                    redirect_server = extracted;
                }
            }

            if (redirect_server) {
                wc_output_log_message("DEBUG",
                                       "Redirecting to: %s",
                                       redirect_server);

                if (strcmp(redirect_server, current_target) == 0) {
                    wc_output_log_message("DEBUG",
                                           "Redirect server same as current target, stopping redirect");
                    free(redirect_server);
                    redirect_server = NULL;

                    if (combined_result == NULL) {
                        combined_result = result;
                    } else {
                        size_t new_len = strlen(combined_result) + strlen(result) + 100;
                        char* new_combined = (char*)malloc(new_len);
                        if (new_combined) {
                            snprintf(new_combined,
                                     new_len,
                                     "%s\n=== Additional query to %s ===\n%s",
                                     combined_result,
                                     current_target,
                                     result);
                            free(combined_result);
                            free(result);
                            combined_result = new_combined;
                        } else {
                            free(result);
                        }
                    }
                    if (!final_authoritative && current_target) {
                        final_authoritative = wc_safe_strdup(current_target, __func__);
                    }
                    break;
                }

                if (combined_result == NULL) {
                    combined_result = result;
                } else {
                    size_t new_len = strlen(combined_result) + strlen(result) + 100;
                    char* new_combined = (char*)malloc(new_len);
                    if (new_combined) {
                        snprintf(new_combined,
                                 new_len,
                                 "%s\n=== Redirected query to %s ===\n%s",
                                 combined_result,
                                 current_target,
                                 result);
                        free(combined_result);
                        free(result);
                        combined_result = new_combined;
                    } else {
                        free(result);
                    }
                }

                free(current_target);
                int loop = 0;
                for (int i = 0; i < 16 && visited[i]; i++) {
                    if (strcmp(visited[i], redirect_server) == 0) {
                        loop = 1;
                        break;
                    }
                }
                if (!loop) {
                    for (int i = 0; i < 16; i++) {
                        if (!visited[i]) {
                            visited[i] = wc_safe_strdup(redirect_server, __func__);
                            break;
                        }
                    }
                }
                current_target = wc_safe_strdup(redirect_server, __func__);
                free(redirect_server);
                redirect_server = NULL;

                if (!current_target) {
                    wc_output_log_message("DEBUG", "Memory allocation failed for redirect target");
                    break;
                }
                if (loop) {
                    wc_output_log_message("WARN", "Detected redirect loop, stop following redirects");
                    if (!final_authoritative && current_target) {
                        final_authoritative = wc_safe_strdup(current_target, __func__);
                    }
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
                    char* new_combined = (char*)malloc(new_len);
                    if (new_combined) {
                        snprintf(new_combined,
                                 new_len,
                                 "%s\n=== Final query to %s ===\n%s",
                                 combined_result,
                                 current_target,
                                 result);
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
                char* new_combined = (char*)malloc(new_len);
                if (new_combined) {
                    snprintf(new_combined,
                             new_len,
                             "%s\n=== Final query to %s ===\n%s",
                             combined_result,
                             current_target,
                             result);
                    free(combined_result);
                    free(result);
                    combined_result = new_combined;
                } else {
                    free(result);
                }
            }
            if (!final_authoritative && current_target) {
                final_authoritative = wc_safe_strdup(current_target, __func__);
            }
            break;
        }
    }

    if (redirect_count > g_config.max_redirects) {
        wc_output_log_message("DEBUG",
                              "Maximum redirects reached (%d)",
                              g_config.max_redirects);
        if (combined_result) {
            size_t new_len = strlen(combined_result) + 200;
            char* new_result = (char*)malloc(new_len);
            if (new_result) {
                snprintf(new_result,
                         new_len,
                         "Warning: Maximum redirects reached (%d).\n"
                         "You may need to manually query the final server for complete information.\n\n%s",
                         g_config.max_redirects,
                         combined_result);
                free(combined_result);
                combined_result = new_result;
            }
        }
    }

    if (redirect_server) free(redirect_server);
    for (int i = 0; i < 16; i++) {
        if (visited[i]) free(visited[i]);
    }
    if (!final_authoritative && current_target) {
        final_authoritative = wc_safe_strdup(current_target, __func__);
    }
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

    wc_cache_cleanup_expired_entries();
    if (g_config.debug) {
        wc_cache_validate_integrity();
    }

    if (authoritative_server_out) {
        *authoritative_server_out = final_authoritative;
    } else if (final_authoritative) {
        free(final_authoritative);
    }
    return combined_result;
}
