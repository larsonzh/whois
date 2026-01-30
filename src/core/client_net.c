// SPDX-License-Identifier: GPL-3.0-or-later
// Legacy client-side networking helpers preserved for compatibility.

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
#if defined(_WIN32) || defined(__MINGW32__)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#endif

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
#include "wc/wc_ip_pref.h"

static const Config* wc_client_resolve_config(const Config* injected)
{
    static const Config k_zero_config = {0};
    return injected ? injected : &k_zero_config;
}

static char* wc_client_try_wcdns_candidates(const Config* config,
                                            const char* domain,
                                            const wc_dns_bridge_ctx_t* ctx)
{
    const Config* cfg = wc_client_resolve_config(config);
    if (!domain || !*domain || !ctx || !ctx->canonical_host || !*ctx->canonical_host) {
        return NULL;
    }

    wc_dns_candidate_list_t candidates = {0};
    int prefer_v4_first = wc_ip_pref_prefers_ipv4_first(cfg->ip_pref_mode, 0);
    const wc_net_context_t* net_ctx = wc_net_context_get_active();
    const wc_selftest_injection_t* injection = net_ctx ? net_ctx->injection : NULL;
    int rir_pref = WC_RIR_IP_PREF_UNSET;
    if (ctx->rir_hint) {
        if (strcasecmp(ctx->rir_hint, "iana") == 0) rir_pref = cfg->rir_pref_iana;
        else if (strcasecmp(ctx->rir_hint, "arin") == 0) rir_pref = cfg->rir_pref_arin;
        else if (strcasecmp(ctx->rir_hint, "ripe") == 0) rir_pref = cfg->rir_pref_ripe;
        else if (strcasecmp(ctx->rir_hint, "apnic") == 0) rir_pref = cfg->rir_pref_apnic;
        else if (strcasecmp(ctx->rir_hint, "lacnic") == 0) rir_pref = cfg->rir_pref_lacnic;
        else if (strcasecmp(ctx->rir_hint, "afrinic") == 0) rir_pref = cfg->rir_pref_afrinic;
        else if (strcasecmp(ctx->rir_hint, "verisign") == 0) rir_pref = cfg->rir_pref_verisign;
    }
    int use_rir_pref = (rir_pref != WC_RIR_IP_PREF_UNSET && !cfg->ipv4_only && !cfg->ipv6_only);
    const Config* cfg_for_dns = cfg;
    Config cfg_override;
    if (use_rir_pref) {
        prefer_v4_first = (rir_pref == WC_RIR_IP_PREF_V4) ? 1 : 0;
        cfg_override = *cfg;
        cfg_override.dns_family_mode = (rir_pref == WC_RIR_IP_PREF_V4)
            ? WC_DNS_FAMILY_MODE_IPV4_ONLY_BLOCK
            : WC_DNS_FAMILY_MODE_IPV6_ONLY_BLOCK;
        cfg_override.dns_family_mode_set = 1;
        cfg_override.dns_family_mode_first = cfg_override.dns_family_mode;
        cfg_override.dns_family_mode_next = cfg_override.dns_family_mode;
        cfg_override.dns_family_mode_first_set = 1;
        cfg_override.dns_family_mode_next_set = 1;
        cfg_for_dns = &cfg_override;
    }

    int build_rc = wc_dns_build_candidates(cfg_for_dns, ctx->canonical_host, ctx->rir_hint,
        prefer_v4_first, 0, &candidates, injection);
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
        wc_cache_log_legacy_dns_event(domain, "legacy-shim");
    }
    return resolved_ip;
}

char* wc_client_resolve_domain(const Config* config, const char* domain)
{
    const Config* cfg = wc_client_resolve_config(config);
    if (!domain || !*domain) {
        return NULL;
    }

    if (cfg->debug) {
        printf("[DEBUG] Resolving domain: %s\n", domain);
    }

    wc_dns_bridge_ctx_t wcdns_ctx = {0};
    wc_dns_bridge_ctx_init(domain, &wcdns_ctx);

    wc_cache_dns_source_t cache_source = WC_CACHE_DNS_SOURCE_NONE;
    char* cached_ip = wc_cache_get_dns_with_source(cfg, domain, &cache_source);
    if (cached_ip) {
        if (cfg->debug) {
            if (cache_source == WC_CACHE_DNS_SOURCE_WCDNS) {
                printf("[DEBUG] Using wc_dns cached entry: %s -> %s\n", domain, cached_ip);
            } else {
                printf("[DEBUG] Using cached DNS: %s -> %s\n", domain, cached_ip);
            }
        }
        return cached_ip;
    }
    wc_cache_dns_source_t neg_source = WC_CACHE_DNS_SOURCE_NONE;
    if (wc_cache_is_negative_dns_cached_with_source(cfg, domain, &neg_source)) {
        if (cfg->debug) {
            if (neg_source == WC_CACHE_DNS_SOURCE_WCDNS) {
                printf("[DEBUG] wc_dns negative cache hit for %s (fast-fail)\n", domain);
            } else {
                printf("[DEBUG] Negative DNS cache hit for %s (fast-fail)\n", domain);
            }
        }
        return NULL;
    }

    char* wc_dns_ip = wc_client_try_wcdns_candidates(cfg, domain, &wcdns_ctx);
    if (wc_dns_ip) {
        wc_cache_set_dns(cfg, domain, wc_dns_ip);
        if (cfg->debug) {
            printf("[DEBUG] Resolved %s via wc_dns to %s (cached)\n", domain, wc_dns_ip);
        }
        return wc_dns_ip;
    }

    static int injected_once = 0;
    const wc_selftest_fault_profile_t* fault = wc_selftest_fault_profile();
    if (fault && fault->dns_negative && !injected_once) {
        if (strcmp(domain, "selftest.invalid") == 0) {
            if (!cfg->dns_neg_cache_disable) {
                wc_cache_set_negative_dns_with_error(cfg, domain, EAI_FAIL);
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
            wc_cache_set_negative_dns_with_error(cfg, domain, status);
        }
        return NULL;
    }

    char* ip = NULL;
    int resolved_family = AF_UNSPEC;
    struct sockaddr_storage resolved_addr;
    socklen_t resolved_addr_len = 0;
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
        resolved_family = p->ai_family;
        if (p->ai_addr && p->ai_addrlen > 0 && p->ai_addrlen <= (socklen_t)sizeof(resolved_addr)) {
            memcpy(&resolved_addr, p->ai_addr, (size_t)p->ai_addrlen);
            resolved_addr_len = (socklen_t)p->ai_addrlen;
        } else {
            resolved_addr_len = 0;
        }
        break;
    }

    freeaddrinfo(res);

    if (ip) {
        const struct sockaddr* addr_ptr = (resolved_addr_len > 0)
                                              ? (const struct sockaddr*)&resolved_addr
                                              : NULL;
        wc_cache_set_dns_with_addr(cfg,
                       domain,
                       ip,
                       resolved_family,
                       addr_ptr,
                       resolved_addr_len);
        if (cfg->debug) {
            printf("[DEBUG] Resolved %s to %s (cached)\n", domain, ip);
        }
    } else {
        wc_cache_set_negative_dns_with_error(cfg, domain, EAI_FAIL);
    }

    return ip;
}

int wc_client_connect_to_server(const Config* config, const char* host, int port, int* sockfd)
{
    const Config* cfg = wc_client_resolve_config(config);
    if (!host || !sockfd) {
        return -1;
    }

    if (wc_signal_should_terminate()) {
        return -1;
    }

    wc_output_log_message("DEBUG", "Attempting to connect to %s:%d", host, port);

    int cached_sockfd = wc_cache_get_connection(cfg, host, port);
    if (cached_sockfd != -1) {
        *sockfd = cached_sockfd;
        wc_output_log_message("DEBUG", "Using cached connection to %s:%d", host, port);
        monitor_connection_security(host, port, 0);
        return 0;
    }

    struct wc_net_info net_info;
    int timeout_ms = cfg->timeout_sec * 1000;
    int retries = cfg->max_retries;
    wc_net_context_t* net_ctx = wc_net_context_get_active();
    if (!net_ctx) {
        wc_output_log_message("ERROR", "connect_to_server: missing network context for %s:%d", host, port);
        return -1;
    }
    int rc = wc_dial_43(net_ctx, host, (uint16_t)port, timeout_ms, retries, &net_info);
    if (rc != WC_OK || !net_info.connected || net_info.fd < 0) {
        wc_output_log_message("ERROR", "connect_to_server: all connection attempts failed for %s:%d", host, port);
        return -1;
    }

    *sockfd = net_info.fd;
#ifdef _WIN32
    DWORD timeout_ms_dw = (DWORD)(cfg->timeout_sec * 1000);
    setsockopt(*sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms_dw, sizeof(timeout_ms_dw));
    setsockopt(*sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms_dw, sizeof(timeout_ms_dw));
#else
    struct timeval timeout_io = { cfg->timeout_sec, 0 };
    setsockopt(*sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout_io, sizeof(timeout_io));
    setsockopt(*sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout_io, sizeof(timeout_io));
#endif
    wc_output_log_message("DEBUG", "Successfully connected to %s:%d", host, port);
    monitor_connection_security(host, port, 0);
    wc_cache_set_connection(cfg, host, port, *sockfd);
    return 0;
}

int wc_client_connect_with_fallback(const Config* config, const char* domain, int port, int* sockfd)
{
    const Config* cfg = wc_client_resolve_config(config);
    if (!domain || !sockfd) {
        return -1;
    }

    if (wc_client_connect_to_server(cfg, domain, port, sockfd) == 0) {
        return 0;
    }

    char* ip = wc_client_resolve_domain(cfg, domain);
    if (ip) {
        if (wc_client_connect_to_server(cfg, ip, port, sockfd) == 0) {
            free(ip);
            return 0;
        }
        free(ip);
    }

    const char* known_ip = wc_dns_get_known_ip(domain);
    if (known_ip) {
        if (cfg->debug) {
            wc_output_log_message("DEBUG", "connect_with_fallback: DNS resolution failed, trying known IP %s for %s", known_ip, domain);
        }
        if (wc_client_connect_to_server(cfg, known_ip, port, sockfd) == 0) {
            wc_output_log_message("INFO", "connect_with_fallback: Successfully connected using known IP fallback for %s", domain);
            return 0;
        }
        wc_output_log_message("WARN", "connect_with_fallback: Known IP fallback also failed for %s", domain);
    } else if (cfg->debug) {
        wc_output_log_message("DEBUG", "connect_with_fallback: No known IP fallback available for %s", domain);
    }

    wc_output_log_message("ERROR", "connect_with_fallback: All connection attempts failed for %s:%d", domain, port);
    return -1;
}
