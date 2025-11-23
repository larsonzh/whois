// SPDX-License-Identifier: GPL-3.0-or-later
// Legacy client-side networking helpers preserved for compatibility.

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "wc/wc_cache.h"
#include "wc/wc_client_net.h"
#include "wc/wc_config.h"
#include "wc/wc_dns.h"
#include "wc/wc_net.h"
#include "wc/wc_output.h"
#include "wc/wc_seclog.h"
#include "wc/wc_selftest.h"
#include "wc/wc_signal.h"
#include "wc/wc_util.h"

extern Config g_config;

char* wc_client_resolve_domain(const char* domain)
{
    if (!domain || !*domain) {
        return NULL;
    }

    if (g_config.debug) {
        printf("[DEBUG] Resolving domain: %s\n", domain);
    }

    char* cached_ip = wc_cache_get_dns(domain);
    if (cached_ip) {
        if (g_config.debug) {
            printf("[DEBUG] Using cached DNS: %s -> %s\n", domain, cached_ip);
        }
        return cached_ip;
    }
    if (wc_cache_is_negative_dns_cached(domain)) {
        if (g_config.debug) {
            printf("[DEBUG] Negative DNS cache hit for %s (fast-fail)\n", domain);
        }
        return NULL;
    }

    static int injected_once = 0;
    if (wc_selftest_dns_negative_enabled() && !injected_once) {
        if (strcmp(domain, "selftest.invalid") == 0) {
            if (!g_config.dns_neg_cache_disable) {
                wc_cache_set_negative_dns(domain);
                injected_once = 1;
                return NULL;
            }
        }
    }

    struct addrinfo hints;
    struct addrinfo* res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(domain, NULL, &hints, &res);
    if (status != 0) {
        wc_output_log_message("ERROR", "Failed to resolve domain %s: %s", domain, gai_strerror(status));
        if (status == EAI_NONAME || status == EAI_FAIL) {
            wc_cache_set_negative_dns(domain);
        }
        return NULL;
    }

    char* ip = NULL;
    for (struct addrinfo* p = res; p != NULL; p = p->ai_next) {
        void* addr = NULL;
        char ipstr[INET6_ADDRSTRLEN];
        if (p->ai_family == AF_INET) {
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
            addr = &(ipv4->sin_addr);
        } else if (p->ai_family == AF_INET6) {
            struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
            addr = &(ipv6->sin6_addr);
        } else {
            continue;
        }

        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        ip = wc_safe_strdup(ipstr, __func__);
        break;
    }

    freeaddrinfo(res);

    if (ip) {
        wc_cache_set_dns(domain, ip);
        if (g_config.debug) {
            printf("[DEBUG] Resolved %s to %s (cached)\n", domain, ip);
        }
    } else {
        wc_cache_set_negative_dns(domain);
    }

    return ip;
}

int wc_client_connect_to_server(const char* host, int port, int* sockfd)
{
    if (!host || !sockfd) {
        return -1;
    }

    if (wc_signal_should_terminate()) {
        return -1;
    }

    wc_output_log_message("DEBUG", "Attempting to connect to %s:%d", host, port);

    int cached_sockfd = wc_cache_get_connection(host, port);
    if (cached_sockfd != -1) {
        *sockfd = cached_sockfd;
        wc_output_log_message("DEBUG", "Using cached connection to %s:%d", host, port);
        monitor_connection_security(host, port, 0);
        return 0;
    }

    struct wc_net_info net_info;
    int timeout_ms = g_config.timeout_sec * 1000;
    int retries = g_config.max_retries;
    int rc = wc_dial_43(host, (uint16_t)port, timeout_ms, retries, &net_info);
    if (rc != WC_OK || !net_info.connected || net_info.fd < 0) {
        wc_output_log_message("ERROR", "connect_to_server: all connection attempts failed for %s:%d", host, port);
        return -1;
    }

    *sockfd = net_info.fd;
    struct timeval timeout_io = { g_config.timeout_sec, 0 };
    setsockopt(*sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout_io, sizeof(timeout_io));
    setsockopt(*sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout_io, sizeof(timeout_io));
    wc_output_log_message("DEBUG", "Successfully connected to %s:%d", host, port);
    monitor_connection_security(host, port, 0);
    wc_cache_set_connection(host, port, *sockfd);
    return 0;
}

int wc_client_connect_with_fallback(const char* domain, int port, int* sockfd)
{
    if (!domain || !sockfd) {
        return -1;
    }

    if (wc_client_connect_to_server(domain, port, sockfd) == 0) {
        return 0;
    }

    char* ip = wc_client_resolve_domain(domain);
    if (ip) {
        if (wc_client_connect_to_server(ip, port, sockfd) == 0) {
            free(ip);
            return 0;
        }
        free(ip);
    }

    const char* known_ip = wc_dns_get_known_ip(domain);
    if (known_ip) {
        if (g_config.debug) {
            wc_output_log_message("DEBUG", "connect_with_fallback: DNS resolution failed, trying known IP %s for %s", known_ip, domain);
        }
        if (wc_client_connect_to_server(known_ip, port, sockfd) == 0) {
            wc_output_log_message("INFO", "connect_with_fallback: Successfully connected using known IP fallback for %s", domain);
            return 0;
        }
        wc_output_log_message("WARN", "connect_with_fallback: Known IP fallback also failed for %s", domain);
    } else if (g_config.debug) {
        wc_output_log_message("DEBUG", "connect_with_fallback: No known IP fallback available for %s", domain);
    }

    wc_output_log_message("ERROR", "connect_with_fallback: All connection attempts failed for %s:%d", domain, port);
    return -1;
}
