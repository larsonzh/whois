// SPDX-License-Identifier: MIT
// net.c - Phase A skeleton implementations for network helpers
// Feature test macros for POSIX networking (ensure NI_MAXHOST, getaddrinfo etc.)
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#if defined(_WIN32) || defined(__MINGW32__)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif
#include "wc/wc_net.h"
#include "wc/wc_dns.h"
#include "wc/wc_selftest.h"
#include "wc/wc_util.h"
#include <time.h>
#include <limits.h>
// for non-blocking connect/select
#if defined(_WIN32) || defined(__MINGW32__)
/* On Windows, Winsock2 provides select()/fd_set and timeval; avoid POSIX-only headers */
#else
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#endif

// For active-connection tracking via wc_signal
#include "wc/wc_signal.h"

#if defined(_WIN32) || defined(__MINGW32__)
static void wc_net_log_wsa_error_if_debug(const Config* config, const char* stage, int wsa_error) {
    if (!config || !config->debug) return;
    if (wsa_error == 0) wsa_error = WSAGetLastError();
    fprintf(stderr, "[WIN-WSA] stage=%s wsa_error=%d\n", stage, wsa_error);
}
#else
static void wc_net_log_wsa_error_if_debug(const Config* config, const char* stage, int wsa_error) {
    (void)config; (void)stage; (void)wsa_error;
}
#endif

// ---------------------------------------------------------------------------
// Retry pacing & metrics context plumbing
// ---------------------------------------------------------------------------

static wc_net_context_t* g_wc_net_active_ctx = NULL;
static wc_net_context_t* g_wc_net_flush_head = NULL;
static int g_wc_net_flush_hook_registered = 0;

static void wc_net_flush_registered_contexts_internal(void);

int wc_net_register_flush_hook(void)
{
    if (g_wc_net_flush_hook_registered)
        return 0;
    g_wc_net_flush_hook_registered = 1;
    return 1;
}

void wc_net_context_config_init(wc_net_context_config_t* cfg)
{
    if (!cfg) return;
    cfg->pacing_disable = 0;
    cfg->pacing_interval_ms = 60;
    cfg->pacing_jitter_ms = 40;
    cfg->pacing_backoff_factor = 2;
    cfg->pacing_max_ms = 400;
    cfg->retry_scope_all_addrs = 0;
    cfg->retry_metrics_enabled = 0;
    cfg->max_host_addrs = 0;
    cfg->config = NULL;
    cfg->injection = NULL;
}

static void wc_net_context_register_for_flush(wc_net_context_t* ctx)
{
    if (!ctx || ctx->registered_for_flush)
        return;
    ctx->next_registered = g_wc_net_flush_head;
    g_wc_net_flush_head = ctx;
    ctx->registered_for_flush = 1;
    wc_net_register_flush_hook();
}

int wc_net_context_init(wc_net_context_t* ctx, const wc_net_context_config_t* cfg)
{
    if (!ctx) return -1;
    wc_net_context_config_t defaults;
    wc_net_context_config_init(&defaults);
    wc_net_context_config_t effective = defaults;
    if (cfg) {
        if (cfg->pacing_disable >= 0)
            effective.pacing_disable = cfg->pacing_disable ? 1 : 0;
        if (cfg->pacing_interval_ms >= 0)
            effective.pacing_interval_ms = cfg->pacing_interval_ms;
        if (cfg->pacing_jitter_ms >= 0)
            effective.pacing_jitter_ms = cfg->pacing_jitter_ms;
        if (cfg->pacing_backoff_factor >= 0)
            effective.pacing_backoff_factor = cfg->pacing_backoff_factor;
        if (cfg->pacing_max_ms >= 0)
            effective.pacing_max_ms = cfg->pacing_max_ms;
        if (cfg->retry_scope_all_addrs >= 0)
            effective.retry_scope_all_addrs = cfg->retry_scope_all_addrs ? 1 : 0;
        if (cfg->retry_metrics_enabled >= 0)
            effective.retry_metrics_enabled = cfg->retry_metrics_enabled ? 1 : 0;
        if (cfg->max_host_addrs >= 0)
            effective.max_host_addrs = cfg->max_host_addrs;
    }
    ctx->cfg = effective;
    ctx->attempts = 0;
    ctx->successes = 0;
    ctx->failures = 0;
    ctx->total_sleep_ms = 0;
    ctx->latency_count = 0;
    memset(ctx->latency_ms, 0, sizeof(ctx->latency_ms));
    ctx->err_timeout = 0;
    ctx->err_refused = 0;
    ctx->err_net_unreach = 0;
    ctx->err_host_unreach = 0;
    ctx->err_addr_na = 0;
    ctx->err_intr = 0;
    ctx->err_other = 0;
    ctx->selftest_fail_first_once = 0;
    ctx->selftest_fault_version_seen = 0;
    ctx->registered_for_flush = 0;
    ctx->next_registered = NULL;
    ctx->config = cfg ? cfg->config : NULL;
    ctx->injection = cfg ? cfg->injection : NULL;
    wc_net_context_register_for_flush(ctx);
    return 0;
}

void wc_net_context_shutdown(wc_net_context_t* ctx)
{
    if (!ctx) return;
    if (g_wc_net_active_ctx == ctx) {
        g_wc_net_active_ctx = NULL;
    }
}

void wc_net_context_set_active(wc_net_context_t* ctx)
{
    g_wc_net_active_ctx = ctx;
}

wc_net_context_t* wc_net_context_get_active(void)
{
    return g_wc_net_active_ctx;
}

int wc_net_context_retry_metrics_enabled(const wc_net_context_t* ctx)
{
    return (ctx && ctx->cfg.retry_metrics_enabled) ? 1 : 0;
}

int wc_net_retry_metrics_enabled(void)
{
    return wc_net_context_retry_metrics_enabled(wc_net_context_get_active());
}

static wc_net_context_t* wc_net_resolve_context(wc_net_context_t* ctx)
{
    if (ctx)
        return ctx;
    return g_wc_net_active_ctx;
}

static inline void wc_net_classify_errno(wc_net_context_t* ctx, int e)
{
    if (!ctx || e == 0) return;
    switch (e) {
        case ETIMEDOUT: ctx->err_timeout++; break;
        case ECONNREFUSED: ctx->err_refused++; break;
        case ENETUNREACH: ctx->err_net_unreach++; break;
        case EHOSTUNREACH: ctx->err_host_unreach++; break;
        case EADDRNOTAVAIL: ctx->err_addr_na++; break;
        case EINTR: ctx->err_intr++; break;
        default: ctx->err_other++; break;
    }
}

static void wc_net_retry_metrics_flush_ctx(wc_net_context_t* ctx)
{
    if (!wc_net_context_retry_metrics_enabled(ctx))
        return;
    unsigned cnt = ctx->latency_count;
    unsigned long sum = 0;
    unsigned minv = UINT_MAX;
    unsigned maxv = 0;
    for (unsigned i = 0; i < cnt; i++) {
        unsigned v = ctx->latency_ms[i];
        sum += v;
        if (v < minv) minv = v;
        if (v > maxv) maxv = v;
    }
    double avg = (cnt ? (double)sum / (double)cnt : 0.0);
    unsigned p95 = 0;
    if (cnt) {
        unsigned* tmp = (unsigned*)malloc(sizeof(unsigned) * cnt);
        if (tmp) {
            memcpy(tmp, ctx->latency_ms, sizeof(unsigned) * cnt);
            for (unsigned i = 1; i < cnt; i++) {
                unsigned key = tmp[i];
                int j = (int)i - 1;
                while (j >= 0 && tmp[j] > key) {
                    tmp[j + 1] = tmp[j];
                    j--;
                }
                tmp[j + 1] = key;
            }
            unsigned idx = (unsigned)((cnt * 95) / 100);
            if (idx >= cnt) idx = cnt - 1;
            p95 = tmp[idx];
            free(tmp);
        }
    }
    fprintf(stderr,
        "[RETRY-METRICS] attempts=%u successes=%u failures=%u min_ms=%u max_ms=%u avg_ms=%.1f p95_ms=%u sleep_ms=%u\n",
        ctx->attempts,
        ctx->successes,
        ctx->failures,
        (minv == UINT_MAX ? 0 : minv),
        maxv,
        avg,
        p95,
        ctx->total_sleep_ms);

    if (ctx->failures > 0) {
        fprintf(stderr,
            "[RETRY-ERRORS] timeouts=%u refused=%u net_unreach=%u host_unreach=%u addr_na=%u interrupted=%u other=%u\n",
            ctx->err_timeout,
            ctx->err_refused,
            ctx->err_net_unreach,
            ctx->err_host_unreach,
            ctx->err_addr_na,
            ctx->err_intr,
            ctx->err_other);
    }
}

static void wc_net_flush_registered_contexts_internal(void)
{
    for (wc_net_context_t* ctx = g_wc_net_flush_head; ctx; ctx = ctx->next_registered) {
        wc_net_retry_metrics_flush_ctx(ctx);
    }
}

void wc_net_flush_registered_contexts(void)
{
    wc_net_flush_registered_contexts_internal();
}

static void wc_net_record_latency(wc_net_context_t* ctx, struct timespec t0){
    if(!wc_net_context_retry_metrics_enabled(ctx)) return;
    struct timespec t1; clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (long)((t1.tv_sec - t0.tv_sec)*1000 + (t1.tv_nsec - t0.tv_nsec)/1000000);
    if (ms < 0) {
        ms = 0;
    }
    if (ctx->latency_count < WC_NET_LATENCY_CAP) {
        ctx->latency_ms[ctx->latency_count++] = (unsigned)ms;
    }
}

static void wc_net_sleep_between_attempts_if_enabled(wc_net_context_t* ctx, int attempt_index, int total_attempts){
    // attempt_index: 0-based index of the just-completed failed attempt
    if(attempt_index+1 >= total_attempts) return; // nothing to sleep if last

    if (!ctx || ctx->cfg.pacing_disable) return;
    long base = ctx->cfg.pacing_interval_ms;
    long jitter_limit = ctx->cfg.pacing_jitter_ms;
    long backoff_factor = ctx->cfg.pacing_backoff_factor;
    long max_ms = ctx->cfg.pacing_max_ms;
    if (base <= 0) return;

    long jitter = 0; if(jitter_limit>0){ jitter = rand() % (int)(jitter_limit + 1); }

    // Compute scaled base using attempt_index with exponential backoff and cap
    long scaled = base;
    for (int i = 0; i < attempt_index; i++) {
        if (backoff_factor <= 1) break;
        if (scaled > (LONG_MAX / backoff_factor)) { scaled = LONG_MAX; break; }
        scaled *= backoff_factor;
        if (scaled >= max_ms) { scaled = max_ms; break; }
    }
    long sleep_ms = scaled + jitter;
    if (sleep_ms > max_ms) sleep_ms = max_ms;
    if (sleep_ms <= 0) return;

    struct timespec ts; ts.tv_sec = (time_t)(sleep_ms/1000); ts.tv_nsec = (long)((sleep_ms%1000)*1000000L);
    nanosleep(&ts,NULL);
    ctx->total_sleep_ms += (unsigned)(sleep_ms > 0 ? sleep_ms : 0);
}

static void wc_net_info_init(struct wc_net_info* n){ if(n){ n->fd=-1; n->ip[0]='\0'; n->connected=0; n->err=WC_ERR_INTERNAL; n->last_errno=0; }}

static void wc_net_sync_fault_profile(wc_net_context_t* ctx)
{
    if (!ctx)
        return;
    const wc_selftest_injection_t* injection = ctx->injection;
    if (!injection)
        return;
    unsigned ver = injection->fault_version ? injection->fault_version : 1;
    if (ver == ctx->selftest_fault_version_seen)
        return;
    ctx->selftest_fail_first_once = injection->fault.net_fail_first_once ? 1 : 0;
    ctx->selftest_fault_version_seen = ver;
}

int wc_dial_43(wc_net_context_t* ctx,
               const char* host,
               uint16_t port,
               int timeout_ms,
               int retries,
               struct wc_net_info* out) {
    wc_net_context_t* net_ctx = wc_net_resolve_context(ctx);
    if (!net_ctx) {
        if (out) {
            wc_net_info_init(out);
            out->err = WC_ERR_INVALID;
            out->last_errno = EINVAL;
        }
        return WC_ERR_INVALID;
    }
    if (!host || !out) return WC_ERR_INVALID;
    wc_net_sync_fault_profile(net_ctx);
    if (timeout_ms <= 0) {
        if (out) {
            wc_net_info_init(out);
            out->err = WC_ERR_INVALID;
            out->last_errno = EINVAL;
        }
        return WC_ERR_INVALID;
    }
    wc_net_info_init(out);
    const Config* config = net_ctx ? net_ctx->config : NULL;
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%u", (unsigned)port);
    struct addrinfo hints; memset(&hints,0,sizeof(hints)); hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
#ifdef AI_ADDRCONFIG
    hints.ai_flags = AI_ADDRCONFIG; // prefer addresses valid for the local configuration
#else
    hints.ai_flags = 0;
#endif
    struct addrinfo* res = NULL;
    int gerr = 0; int gai_tries = 0;
    do {
        gerr = getaddrinfo(host, portbuf, &hints, &res);
        if (gerr == EAI_AGAIN && gai_tries < 2) {
            struct timespec ts; ts.tv_sec = 0; ts.tv_nsec = 100*1000*1000L; // 100ms
            nanosleep(&ts, NULL);
        }
        gai_tries++;
    } while (gerr == EAI_AGAIN && gai_tries < 3);
    if (gerr != 0) {
        if (config && config->debug) {
            fprintf(stderr, "[NET-DEBUG] getaddrinfo host=%s port=%s err=%d tries=%d\n", host, portbuf, gerr, gai_tries);
        }
        out->err = WC_ERR_IO; return out->err;
    }
    if (config && config->debug) {
        int idx = 0;
        for (struct addrinfo* rp_dbg = res; rp_dbg; rp_dbg = rp_dbg->ai_next, ++idx) {
            char dbg_host[NI_MAXHOST]; dbg_host[0] = '\0';
            if (getnameinfo(rp_dbg->ai_addr, rp_dbg->ai_addrlen, dbg_host, sizeof(dbg_host), NULL, 0, NI_NUMERICHOST) != 0) {
                strncpy(dbg_host, "unknown", sizeof(dbg_host)-1); dbg_host[sizeof(dbg_host)-1] = '\0';
            }
            fprintf(stderr, "[NET-DEBUG] addr[%d] family=%d host=%s\n", idx, rp_dbg->ai_family, dbg_host);
        }
    }
    int fd = -1; struct addrinfo* rp; int success=0; int addr_index=0;
    int addr_limit = net_ctx->cfg.max_host_addrs;
    int config_limit = (config ? config->max_host_addrs : 0);
    if (config_limit > 0 && (addr_limit <= 0 || config_limit < addr_limit)) {
        // Favor the effective Config limit when present; also backfill if ctx missed it.
        addr_limit = config_limit;
    }
    if (config && config->debug) {
        fprintf(stderr, "[NET-DEBUG] host=%s max-host-addrs=%d (ctx=%d cfg=%d)\n",
                host,
                addr_limit,
                net_ctx->cfg.max_host_addrs,
                config_limit);
    }
    for (rp = res; rp; rp = rp->ai_next, addr_index++) {
        if (addr_limit > 0 && addr_index >= addr_limit) {
            if (config && config->debug) {
                fprintf(stderr, "[NET-DEBUG] host=%s max-host-addrs-hit limit=%d addr_index=%d\n",
                    host, addr_limit, addr_index);
            }
            break;
        }
        if (!(rp->ai_family==AF_INET || rp->ai_family==AF_INET6)) continue;
        int per_tries = (retries < 1 ? 1 : retries);
        if (!net_ctx->cfg.retry_scope_all_addrs && addr_index > 0) per_tries = 1; // default: subsequent addresses once
        for (int atry=0; atry<per_tries; ++atry) {
            if (config && config->debug) {
                char dbg_host[NI_MAXHOST]; dbg_host[0] = '\0';
                if (getnameinfo(rp->ai_addr, rp->ai_addrlen, dbg_host, sizeof(dbg_host), NULL, 0, NI_NUMERICHOST) != 0) {
                    strncpy(dbg_host, "unknown", sizeof(dbg_host)-1); dbg_host[sizeof(dbg_host)-1] = '\0';
                }
                fprintf(stderr, "[NET-DEBUG] attempt=%u addr_index=%d try=%d/%d family=%d host=%s\n", net_ctx->attempts+1, addr_index, atry+1, per_tries, rp->ai_family, dbg_host);
            }
            struct timespec t0; if(wc_net_context_retry_metrics_enabled(net_ctx)) clock_gettime(CLOCK_MONOTONIC,&t0);
            net_ctx->attempts++;
            int wsa_err = 0;
            fd = (int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
#ifdef _WIN32
            if ((SOCKET)fd == INVALID_SOCKET) wsa_err = WSAGetLastError();
#endif
            if (fd < 0){ net_ctx->failures++; out->last_errno = errno; wc_net_classify_errno(net_ctx, errno); wc_net_log_wsa_error_if_debug(config, "socket", wsa_err); goto per_try_end; }
#ifndef _WIN32
            int flags = fcntl(fd, F_GETFL, 0);
            if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#else
            {
                u_long nb = 1;
                ioctlsocket(fd, FIONBIO, &nb);
            }
#endif
            int c_rc = connect(fd, rp->ai_addr, rp->ai_addrlen);
#ifdef _WIN32
            if (c_rc != 0) {
                wsa_err = WSAGetLastError();
                if (wsa_err == WSAEWOULDBLOCK) {
                    // Treat non-blocking in-progress like EINPROGRESS so we enter select() path.
                    errno = EINPROGRESS;
                    // Clear the transient WSAEWOULDBLOCK so we don't log a stale code later.
                    wsa_err = 0;
                }
            }
#endif
            int connected_now = 0;
            if (c_rc == 0) { connected_now = 1; out->last_errno=0; }
            else if (errno == EINPROGRESS) {
                fd_set wfds; FD_ZERO(&wfds); FD_SET(fd, &wfds);
                struct timeval tv; tv.tv_sec = timeout_ms/1000; tv.tv_usec = (timeout_ms%1000)*1000;
                int sel = select(fd+1, NULL, &wfds, NULL, &tv);
                if (sel == 1 && FD_ISSET(fd, &wfds)) {
#ifdef _WIN32
                    int soerr = 0; int slen = sizeof(soerr);
                    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&soerr, &slen) == 0 && soerr == 0) { connected_now = 1; out->last_errno = 0; }
                    else { errno = soerr; out->last_errno = errno; wsa_err = soerr; }
#else
                    int soerr = 0; socklen_t slen = sizeof(soerr);
                    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) == 0 && soerr == 0) { connected_now = 1; out->last_errno = 0; }
                    else { errno = soerr; out->last_errno = errno; }
#endif
                } else {
#ifdef _WIN32
                    if (sel == 0) {
                        wsa_err = WSAETIMEDOUT;
                    } else if (sel < 0) {
                        wsa_err = WSAGetLastError();
                    }
#endif
                    errno = (sel==0?ETIMEDOUT:errno); out->last_errno = errno;
                }
            } else { out->last_errno = errno; }
            if (connected_now) {
                /* restore blocking mode */
#ifndef _WIN32
                if (flags >= 0) fcntl(fd, F_SETFL, flags);
#else
                {
                    u_long nb = 0;
                    ioctlsocket(fd, FIONBIO, &nb);
                }
#endif
                if (net_ctx->selftest_fail_first_once && addr_index==0 && atry==0) {
                    wc_net_record_latency(net_ctx, t0);
                    net_ctx->failures++;
                    int debug_enabled = config ? config->debug : 0;
                    wc_safe_close(&fd, "wc_dial_43(selftest)", debug_enabled);
                    out->last_errno=ECONNABORTED;
                    wc_net_classify_errno(net_ctx, out->last_errno);
                    net_ctx->selftest_fail_first_once = 0;
                    goto per_try_end;
                }
                wc_net_record_latency(net_ctx, t0);
                net_ctx->successes++;
                if (wc_net_context_retry_metrics_enabled(net_ctx) && net_ctx->latency_count > 0) {
                    unsigned last = net_ctx->latency_ms[net_ctx->latency_count - 1];
                    fprintf(stderr,
                        "[RETRY-METRICS-INSTANT] attempt=%u success=1 latency_ms=%u total_attempts=%u\n",
                        net_ctx->attempts,
                        last,
                        net_ctx->attempts);
                }
                out->fd = fd; out->connected = 1; out->err = WC_OK;
                char hostbuf[NI_MAXHOST];
                if (getnameinfo(rp->ai_addr, rp->ai_addrlen, hostbuf, sizeof(hostbuf), NULL, 0, NI_NUMERICHOST)==0) { strncpy(out->ip, hostbuf, sizeof(out->ip)-1); out->ip[sizeof(out->ip)-1]='\0'; }
                else { strncpy(out->ip, "unknown", sizeof(out->ip)-1); }
                success=1; // break out of both loops
            } else {
                int debug_enabled = config ? config->debug : 0;
                wc_net_record_latency(net_ctx, t0); net_ctx->failures++; wc_safe_close(&fd, "wc_dial_43(connect_fail)", debug_enabled); wc_net_classify_errno(net_ctx, errno); wc_net_log_wsa_error_if_debug(config, "connect", wsa_err);
            }
            // Feed DNS health memory with per-attempt outcome. This is
            // observability-only in Phase 3 step 2 and does not alter
            // dialing behavior.
            wc_dns_health_note_result(config, host, rp->ai_family, connected_now);
        per_try_end:
            if (success) break;
            if (atry+1 < per_tries) { wc_net_sleep_between_attempts_if_enabled(net_ctx, atry, per_tries); }
        }
        if (success) break;
    }
    freeaddrinfo(res);
    if (!out->connected) { out->err = WC_ERR_IO; }
    return out->err;
}

// Convenience helper: dial + register active connection for signal handling.
// This is a thin wrapper around wc_dial_43() and
// wc_signal_register_active_connection(), keeping dialing semantics unchanged.
int wc_net_dial_and_register(wc_net_context_t* ctx,
                             const char* host,
                             uint16_t port,
                             int timeout_ms,
                             int retries,
                             struct wc_net_info* out) {
    int rc = wc_dial_43(ctx, host, port, timeout_ms, retries, out);
    if (rc == WC_OK && out && out->connected && out->fd >= 0) {
        wc_signal_register_active_connection(host, (int)port, out->fd);
    }
    return rc;
}

void wc_net_close_and_unregister(int* fd) {
    if (!fd) return;
    if (*fd >= 0) {
        wc_signal_unregister_active_connection();
        int debug_enabled = 0;
        wc_net_context_t* ctx = wc_net_context_get_active();
        if (ctx && ctx->config)
            debug_enabled = ctx->config->debug;
        wc_safe_close(fd, "wc_net_close_and_unregister", debug_enabled);
    }
}

ssize_t wc_send_all(int fd, const void* buf, size_t len, int timeout_ms) {
    (void)timeout_ms; // placeholder
    const char* p = (const char*)buf;
    size_t left = len;
    while (left > 0) {
        ssize_t w = send(fd, p, left, 0);
        if (w < 0) return -1;
        left -= (size_t)w; p += w;
    }
    return (ssize_t)len;
}

ssize_t wc_recv_until_idle(int fd, char** out_buf, size_t* out_len, int idle_timeout_ms, int max_bytes) {
    if (!out_buf || !out_len) return -1;
    if (idle_timeout_ms <= 0 || max_bytes <= 0) return -1;

    size_t cap = (size_t)max_bytes;
    char* buf = (char*)malloc(cap + 1);
    if (!buf) return -1;

    size_t used = 0;
    // We'll use a small sleep loop + non-blocking peek with select for portability.
    // This avoids platform-specific poll intricacies for now.
    for (;;) {
        if (used >= cap) break; // full
        fd_set rfds; FD_ZERO(&rfds); FD_SET(fd, &rfds);
        struct timeval tv; tv.tv_sec = idle_timeout_ms / 1000; tv.tv_usec = (idle_timeout_ms % 1000) * 1000;
        int sel = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) { if (errno == EINTR) continue; break; }
        if (sel == 0) {
            // idle timeout reached
            break;
        }
        if (!FD_ISSET(fd, &rfds)) {
            // unexpected; treat as idle
            break;
        }
        ssize_t r = recv(fd, buf + used, cap - used, 0);
        if (r < 0) {
            if (errno == EINTR) continue; // retry
            break; // error -> stop, we'll return what we have if any
        } else if (r == 0) {
            // peer closed
            break;
        } else {
            used += (size_t)r;
            // Short read may indicate we drained; loop again to see if more arrives before idle timeout
            // We reset idle timer each successful read by re-entering select with full timeout
        }
    }
    buf[used] = '\0';
    *out_buf = buf; *out_len = used;
    return (ssize_t)used;
}
