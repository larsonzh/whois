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
#include "wc/wc_server.h"
#include "wc/wc_net.h"
#include "wc/wc_output.h"
#include "wc/wc_seclog.h"
#include "wc/wc_selftest.h"
#include "wc/wc_signal.h"
#include "wc/wc_util.h"

extern Config g_config;

static int wc_client_should_trace_legacy_dns(void)
{
    return g_config.debug || wc_net_retry_metrics_enabled();
}

static void wc_client_log_legacy_dns_cache(const char* domain, const char* status)
{
    if (!wc_client_should_trace_legacy_dns()) {
        return;
    }
    fprintf(stderr,
            "[DNS-CACHE-LGCY] domain=%s status=%s\n",
            (domain && *domain) ? domain : "unknown",
            (status && *status) ? status : "unknown");
}

typedef struct {
    const char* lookup_host;
    const char* rir_hint;
} wc_client_wcdns_ctx_t;

static wc_client_wcdns_ctx_t wc_client_build_wcdns_ctx(const char* domain)
{
    wc_client_wcdns_ctx_t ctx = {0};
    if (!domain || !*domain) {
        return ctx;
    }
    ctx.rir_hint = wc_guess_rir(domain);
    const char* canonical_from_alias = wc_dns_canonical_host_for_rir(domain);
    if (canonical_from_alias) {
        ctx.lookup_host = canonical_from_alias;
    } else if (ctx.rir_hint && strcmp(ctx.rir_hint, "unknown") != 0) {
        const char* canonical_from_rir = wc_dns_canonical_host_for_rir(ctx.rir_hint);
        if (canonical_from_rir) ctx.lookup_host = canonical_from_rir;
    }
    if (!ctx.lookup_host) {
        ctx.lookup_host = domain;
    }
    return ctx;
}

static void wc_client_sync_wcdns_negative(const wc_client_wcdns_ctx_t* ctx, int err)
{
    if (!ctx || !ctx->lookup_host || !*ctx->lookup_host) {
        return;
    }
    wc_dns_negative_cache_store(ctx->lookup_host, err);
}

static int wc_client_try_wcdns_negative(const char* domain, const wc_client_wcdns_ctx_t* ctx)
{
    if (!domain || !*domain || !ctx || !ctx->lookup_host || !*ctx->lookup_host) {
        return 0;
    }
    int neg_err = 0;
    if (wc_dns_negative_cache_lookup(ctx->lookup_host, &neg_err)) {
        wc_client_log_legacy_dns_cache(domain, "neg-bridge");
        wc_cache_set_negative_dns(domain);
        return 1;
    }
    return 0;
}

static char* wc_client_try_wcdns_candidates(const char* domain, const wc_client_wcdns_ctx_t* ctx)
{
    if (!domain || !*domain || !ctx || !ctx->lookup_host || !*ctx->lookup_host) {
        return NULL;
    }

    wc_dns_candidate_list_t candidates = {0};
    int build_rc = wc_dns_build_candidates(ctx->lookup_host, ctx->rir_hint, &candidates);
    if (build_rc != 0) {
        wc_dns_candidate_list_free(&candidates);
        return NULL;
    }

    char* resolved_ip = NULL;
    for (int i = 0; i < candidates.count; ++i) {
        const char* entry = candidates.items[i];
        if (entry && wc_dns_is_ip_literal(entry)) {
            resolved_ip = wc_safe_strdup(entry, __func__);
            break;
        }
    }

    wc_dns_candidate_list_free(&candidates);

    if (resolved_ip) {
        wc_client_log_legacy_dns_cache(domain, "bridge-hit");
    }
    return resolved_ip;
}

char* wc_client_resolve_domain(const char* domain)
{
    if (!domain || !*domain) {
        return NULL;
    }

    if (g_config.debug) {
        printf("[DEBUG] Resolving domain: %s\n", domain);
    }

    wc_client_wcdns_ctx_t wcdns_ctx = {0};
    if (g_config.dns_use_wc_dns) {
        wcdns_ctx = wc_client_build_wcdns_ctx(domain);
    }

    char* cached_ip = wc_cache_get_dns(domain);
    if (cached_ip) {
        wc_client_log_legacy_dns_cache(domain, "hit");
        if (g_config.debug) {
            printf("[DEBUG] Using cached DNS: %s -> %s\n", domain, cached_ip);
        }
        return cached_ip;
    }
    if (wc_cache_is_negative_dns_cached(domain)) {
        wc_client_log_legacy_dns_cache(domain, "neg-hit");
        if (g_config.debug) {
            printf("[DEBUG] Negative DNS cache hit for %s (fast-fail)\n", domain);
        }
        return NULL;
    }

    if (g_config.dns_use_wc_dns && wc_client_try_wcdns_negative(domain, &wcdns_ctx)) {
        return NULL;
    }
    wc_client_log_legacy_dns_cache(domain, "miss");

    if (g_config.dns_use_wc_dns) {
        char* wc_dns_ip = wc_client_try_wcdns_candidates(domain, &wcdns_ctx);
        if (wc_dns_ip) {
            wc_cache_set_dns(domain, wc_dns_ip);
            if (g_config.debug) {
                printf("[DEBUG] Resolved %s via wc_dns to %s (cached)\n", domain, wc_dns_ip);
            }
            return wc_dns_ip;
        }
    }

    static int injected_once = 0;
    if (wc_selftest_dns_negative_enabled() && !injected_once) {
        if (strcmp(domain, "selftest.invalid") == 0) {
            if (!g_config.dns_neg_cache_disable) {
                wc_cache_set_negative_dns(domain);
                if (g_config.dns_use_wc_dns) {
                    wc_client_sync_wcdns_negative(&wcdns_ctx, EAI_FAIL);
                }
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
            if (g_config.dns_use_wc_dns) {
                wc_client_sync_wcdns_negative(&wcdns_ctx, status);
            }
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
        if (g_config.dns_use_wc_dns) {
            wc_client_sync_wcdns_negative(&wcdns_ctx, EAI_FAIL);
        }
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
