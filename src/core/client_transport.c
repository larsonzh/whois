// SPDX-License-Identifier: GPL-3.0-or-later
// Legacy socket send/receive helpers for WHOIS client compatibility.

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "wc/wc_client_transport.h"
#include "wc/wc_config.h"
#include "wc/wc_output.h"
#include "wc/wc_runtime.h"
#include "wc/wc_protocol_safety.h"
#include "wc/wc_signal.h"
#include "wc/wc_util.h"

static const Config* wc_client_transport_config(const Config* injected)
{
    static const Config k_zero_config = {0};
    const Config* cfg = injected ? injected : wc_runtime_config();
    return cfg ? cfg : &k_zero_config;
}

int wc_client_send_query(const Config* config, int sockfd, const char* query)
{
    const Config* cfg = wc_client_transport_config(config);
    if (sockfd < 0 || !query) {
        return -1;
    }

    char query_msg[256];
    snprintf(query_msg, sizeof(query_msg), "%s\r\n", query);
    int sent = (int)send(sockfd, query_msg, strlen(query_msg), 0);
    if (cfg->debug) {
        printf("[DEBUG] Sending query: %s (%d bytes)\n", query, sent);
    }
    return sent;
}

char* wc_client_receive_response(const Config* config, int sockfd)
{
    const Config* cfg = wc_client_transport_config(config);
    if (sockfd < 0) {
        return NULL;
    }

    if (cfg->debug) {
        printf("[DEBUG] Attempting to allocate response buffer of size %zu bytes\n",
               cfg->buffer_size);
    }

    if (cfg->buffer_size > 100U * 1024U * 1024U && cfg->debug) {
        printf("[WARNING] Requested buffer size is very large (%zu MB)\n",
               cfg->buffer_size / (1024U * 1024U));
    }

    char* buffer = wc_safe_malloc(cfg->buffer_size, __func__);
    ssize_t total_bytes = 0;
    fd_set read_fds;
    struct timeval timeout;

    while ((size_t)total_bytes < cfg->buffer_size - 1) {
        if (wc_signal_should_terminate()) {
            wc_output_log_message("INFO", "Receive interrupted by signal");
            break;
        }
        FD_ZERO(&read_fds);
        FD_SET(sockfd, &read_fds);
        timeout.tv_sec = cfg->timeout_sec;
        timeout.tv_usec = 0;

        int ready = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);
        if (ready < 0) {
            if (cfg->debug) {
                printf("[DEBUG] Select error after %zd bytes: %s\n", total_bytes, strerror(errno));
            }
            break;
        } else if (ready == 0) {
            if (cfg->debug) {
                printf("[DEBUG] Select timeout after %zd bytes\n", total_bytes);
            }
            break;
        }

        ssize_t n = recv(sockfd,
                         buffer + total_bytes,
                         cfg->buffer_size - total_bytes - 1,
                         0);
        if (n < 0) {
            if (cfg->debug) {
                printf("[DEBUG] Read error after %zd bytes: %s\n", total_bytes, strerror(errno));
            }
            break;
        } else if (n == 0) {
            if (cfg->debug) {
                printf("[DEBUG] Connection closed by peer after %zd bytes\n", total_bytes);
            }
            break;
        }

        total_bytes += n;
        if (cfg->debug) {
            printf("[DEBUG] Received %zd bytes, total %zd bytes\n", n, total_bytes);
        }

        if (total_bytes > 1000) {
            if (strstr(buffer, "source:") || strstr(buffer, "person:") ||
                strstr(buffer, "inetnum:") || strstr(buffer, "NetRange:")) {
                if (cfg->debug) {
                    printf("[DEBUG] Detected complete WHOIS response\n");
                }
            }
        }
    }

    if (total_bytes <= 0) {
        free(buffer);
        if (cfg->debug) {
            printf("[DEBUG] No response received\n");
        }
        return NULL;
    }

    buffer[total_bytes] = '\0';

    if (!wc_protocol_validate_response_data(buffer, total_bytes)) {
        wc_output_log_message("ERROR", "Response data validation failed");
        free(buffer);
        return NULL;
    }

    if (!wc_protocol_validate_whois_response(buffer, total_bytes)) {
        wc_output_log_message("ERROR", "WHOIS protocol response validation failed");
        free(buffer);
        return NULL;
    }

    if (!wc_protocol_check_response_integrity(buffer, total_bytes)) {
        wc_output_log_message("ERROR", "WHOIS response integrity check failed");
        free(buffer);
        return NULL;
    }

    if (wc_protocol_detect_anomalies(buffer)) {
        wc_output_log_message("WARN", "Protocol anomalies detected in WHOIS response");
    }

    if (cfg->debug) {
        printf("[DEBUG] Response received successfully (%zd bytes)\n", total_bytes);
        printf("[DEBUG] ===== RESPONSE PREVIEW =====\n");
        printf("%.500s\n", buffer);
        if (total_bytes > 500) {
            printf("... (truncated)\n");
        }
        printf("[DEBUG] ===== END PREVIEW =====\n");
    }

    return buffer;
}
