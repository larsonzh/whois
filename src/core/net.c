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
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "wc/wc_net.h"
#include "wc/wc_dns.h"
#include <time.h>
#include <limits.h>
// for non-blocking connect/select
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>

// For active-connection tracking via wc_signal
#include "wc/wc_signal.h"

// safe_close is provided by whois_client.c as a shared utility
void safe_close(int* fd, const char* function_name);

// ---------------------------------------------------------------------------
// Retry pacing & metrics (Phase 1: instrumentation-only, no behavioral change
// unless explicitly enabled via environment variable switches)
// ---------------------------------------------------------------------------
// Runtime-configurable (no environment dependency in release builds):
// Use wc_net_set_* setters (declared in wc_net.h) to control pacing/metrics/selftest.

static int g_retry_metrics_enabled = 0;
static unsigned g_retry_attempts = 0;          // total connect() calls attempted
static unsigned g_retry_successes = 0;         // successful connect() calls
static unsigned g_retry_failures = 0;          // failed connect() calls
static unsigned g_retry_total_sleep_ms = 0;    // total artificial sleep inserted
static unsigned g_latency_count = 0;           // number of recorded latencies
// Use macro for compile-time constant size (C does not treat const unsigned as VLA-safe constant)
#define LAT_CAP 256
static unsigned g_latency_ms[LAT_CAP];         // per-attempt latencies (ms)

// Pacing configuration (default-on with recommended values)
static int g_pacing_disable = 0;
static int g_pacing_interval_ms = 60;
static int g_pacing_jitter_ms = 40;
static int g_pacing_backoff_factor = 2;
static int g_pacing_max_ms = 400;

// Selftest fail-first (one-shot)
static int g_selftest_fail_first_once = 0;

// Error classification counters (for diagnostics)
static unsigned g_err_timeout = 0;
static unsigned g_err_refused = 0;
static unsigned g_err_net_unreach = 0;
static unsigned g_err_host_unreach = 0;
static unsigned g_err_addr_na = 0;
static unsigned g_err_intr = 0;
static unsigned g_err_other = 0;

// Retry scope: default 0 (only first resolved address gets multiple retries),
// when set to 1, apply retry count to every resolved address candidate.
static int g_retry_all_addrs = 0;

static inline void wc_net_classify_errno(int e){
    if (e == 0) return;
    switch (e) {
        case ETIMEDOUT: g_err_timeout++; break;
        case ECONNREFUSED: g_err_refused++; break;
        case ENETUNREACH: g_err_net_unreach++; break;
        case EHOSTUNREACH: g_err_host_unreach++; break;
        case EADDRNOTAVAIL: g_err_addr_na++; break;
        case EINTR: g_err_intr++; break;
        default: g_err_other++; break;
    }
}

static void wc_net_retry_metrics_flush(void){
    if (!g_retry_metrics_enabled) return;
    unsigned cnt = g_latency_count;
    unsigned long sum = 0; unsigned minv=UINT_MAX; unsigned maxv=0;
    for(unsigned i=0;i<cnt;i++){ unsigned v=g_latency_ms[i]; sum+=v; if(v<minv) minv=v; if(v>maxv) maxv=v; }
    double avg = (cnt? (double)sum/(double)cnt : 0.0);
    unsigned p95=0; if(cnt){ unsigned* tmp=(unsigned*)malloc(sizeof(unsigned)*cnt); if(tmp){ memcpy(tmp,g_latency_ms,sizeof(unsigned)*cnt); 
            // insertion sort (cnt small)
            for(unsigned i=1;i<cnt;i++){ unsigned key=tmp[i]; int j=(int)i-1; while(j>=0 && tmp[j]>key){ tmp[j+1]=tmp[j]; j--; } tmp[j+1]=key; }
            unsigned idx = (unsigned)((cnt*95)/100); if(idx>=cnt) idx=cnt-1; p95=tmp[idx]; free(tmp); }
    }
    fprintf(stderr,
        "[RETRY-METRICS] attempts=%u successes=%u failures=%u min_ms=%u max_ms=%u avg_ms=%.1f p95_ms=%u sleep_ms=%u\n",
        g_retry_attempts, g_retry_successes, g_retry_failures,
        (minv==UINT_MAX?0:minv), maxv, avg, p95, g_retry_total_sleep_ms);

    // Print error breakdown if any failures occurred
    if (g_retry_failures > 0) {
        fprintf(stderr,
            "[RETRY-ERRORS] timeouts=%u refused=%u net_unreach=%u host_unreach=%u addr_na=%u interrupted=%u other=%u\n",
            g_err_timeout, g_err_refused, g_err_net_unreach, g_err_host_unreach, g_err_addr_na, g_err_intr, g_err_other);
    }
}

static void wc_net_retry_metrics_register_flush_if_needed(void){
    static int registered = 0;
    if (g_retry_metrics_enabled && !registered) {
        atexit(wc_net_retry_metrics_flush);
        registered = 1;
    }
}

static void wc_net_record_latency(struct timespec t0){
    if(!g_retry_metrics_enabled) return;
    struct timespec t1; clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (long)((t1.tv_sec - t0.tv_sec)*1000 + (t1.tv_nsec - t0.tv_nsec)/1000000);
    if (ms < 0) {
        ms = 0;
    }
    if (g_latency_count < LAT_CAP) {
        g_latency_ms[g_latency_count++] = (unsigned)ms;
    }
}

static void wc_net_sleep_between_attempts_if_enabled(int attempt_index, int total_attempts){
    // attempt_index: 0-based index of the just-completed failed attempt
    if(attempt_index+1 >= total_attempts) return; // nothing to sleep if last

    if (g_pacing_disable) return;
    long base = g_pacing_interval_ms;
    long jitter_limit = g_pacing_jitter_ms;
    long backoff_factor = g_pacing_backoff_factor;
    long max_ms = g_pacing_max_ms;
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
    g_retry_total_sleep_ms += (unsigned)(sleep_ms > 0 ? sleep_ms : 0);
}


static void wc_net_info_init(struct wc_net_info* n){ if(n){ n->fd=-1; n->ip[0]='\0'; n->connected=0; n->err=WC_ERR_INTERNAL; n->last_errno=0; }}

int wc_dial_43(const char* host, uint16_t port, int timeout_ms, int retries, struct wc_net_info* out) {
    // Non-blocking connect with user timeout per attempt; preserves retry pacing + metrics.
    wc_net_retry_metrics_register_flush_if_needed();
    if (!host || !out) return WC_ERR_INVALID;
    if (timeout_ms <= 0) timeout_ms = 5000; // fallback to 5s if caller passes 0/neg
    wc_net_info_init(out);
    // Selftest knob: fail the entire first attempt (across all addrinfo) once.
    // g_selftest_fail_first_once is set via wc_net_set_selftest_fail_first()
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
        out->err = WC_ERR_IO; return out->err;
    }
    int fd = -1; struct addrinfo* rp; int success=0; int addr_index=0;
    for (rp = res; rp; rp = rp->ai_next, addr_index++) {
        if (!(rp->ai_family==AF_INET || rp->ai_family==AF_INET6)) continue;
        int per_tries = (retries < 1 ? 1 : retries);
        if (!g_retry_all_addrs && addr_index > 0) per_tries = 1; // default: subsequent addresses are attempted once
        for (int atry=0; atry<per_tries; ++atry) {
            struct timespec t0; if(g_retry_metrics_enabled) clock_gettime(CLOCK_MONOTONIC,&t0);
            g_retry_attempts++;
            fd = (int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd < 0){ g_retry_failures++; out->last_errno = errno; wc_net_classify_errno(errno); goto per_try_end; }
            int flags = fcntl(fd, F_GETFL, 0);
            if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            int c_rc = connect(fd, rp->ai_addr, rp->ai_addrlen);
            int connected_now = 0;
            if (c_rc == 0) { connected_now = 1; out->last_errno=0; }
            else if (errno == EINPROGRESS) {
                fd_set wfds; FD_ZERO(&wfds); FD_SET(fd, &wfds);
                struct timeval tv; tv.tv_sec = timeout_ms/1000; tv.tv_usec = (timeout_ms%1000)*1000;
                int sel = select(fd+1, NULL, &wfds, NULL, &tv);
                if (sel == 1 && FD_ISSET(fd, &wfds)) {
                    int soerr=0; socklen_t slen=sizeof(soerr);
                    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen)==0 && soerr==0) { connected_now=1; out->last_errno=0; }
                    else { errno = soerr; out->last_errno = errno; }
                } else { errno = (sel==0?ETIMEDOUT:errno); out->last_errno = errno; }
            } else { out->last_errno = errno; }
            if (connected_now) {
                if (flags >= 0) fcntl(fd, F_SETFL, flags);
                if (g_selftest_fail_first_once && addr_index==0 && atry==0) { wc_net_record_latency(t0); g_retry_failures++; close(fd); fd=-1; out->last_errno=ECONNABORTED; wc_net_classify_errno(out->last_errno); goto per_try_end; }
                wc_net_record_latency(t0);
                g_retry_successes++;
                if (g_retry_metrics_enabled && g_latency_count > 0) {
                    unsigned last = g_latency_ms[g_latency_count - 1];
                    fprintf(stderr, "[RETRY-METRICS-INSTANT] attempt=%u success=1 latency_ms=%u total_attempts=%u\n", g_retry_attempts, last, g_retry_attempts);
                }
                out->fd = fd; out->connected = 1; out->err = WC_OK;
                char hostbuf[NI_MAXHOST];
                if (getnameinfo(rp->ai_addr, rp->ai_addrlen, hostbuf, sizeof(hostbuf), NULL, 0, NI_NUMERICHOST)==0) { strncpy(out->ip, hostbuf, sizeof(out->ip)-1); out->ip[sizeof(out->ip)-1]='\0'; }
                else { strncpy(out->ip, "unknown", sizeof(out->ip)-1); }
                success=1; // break out of both loops
            } else {
                wc_net_record_latency(t0); g_retry_failures++; close(fd); fd=-1; wc_net_classify_errno(errno);
            }
            // Feed DNS health memory with per-attempt outcome. This is
            // observability-only in Phase 3 step 2 and does not alter
            // dialing behavior.
            wc_dns_health_note_result(host, rp->ai_family, connected_now);
        per_try_end:
            if (success) break;
            if (atry+1 < per_tries) { wc_net_sleep_between_attempts_if_enabled(atry, per_tries); }
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
int wc_net_dial_and_register(const char* host,
                             uint16_t port,
                             int timeout_ms,
                             int retries,
                             struct wc_net_info* out) {
    int rc = wc_dial_43(host, port, timeout_ms, retries, out);
    if (rc == WC_OK && out && out->connected && out->fd >= 0) {
        wc_signal_register_active_connection(host, (int)port, out->fd);
    }
    return rc;
}

void wc_net_close_and_unregister(int* fd) {
    if (!fd) return;
    if (*fd >= 0) {
        wc_signal_unregister_active_connection();
        safe_close(fd, "wc_net_close_and_unregister");
    }
}

// ------------------- Runtime setters -------------------
void wc_net_set_pacing_config(int disable, int interval_ms, int jitter_ms, int backoff_factor, int max_ms) {
    if (disable >= 0) g_pacing_disable = disable ? 1 : 0;
    if (interval_ms >= 0) g_pacing_interval_ms = interval_ms;
    if (jitter_ms >= 0) g_pacing_jitter_ms = jitter_ms;
    if (backoff_factor >= 0) g_pacing_backoff_factor = backoff_factor;
    if (max_ms >= 0) g_pacing_max_ms = max_ms;
}

void wc_net_set_retry_metrics_enabled(int enabled) {
    g_retry_metrics_enabled = enabled ? 1 : 0;
    wc_net_retry_metrics_register_flush_if_needed();
}

int wc_net_retry_metrics_enabled(void) {
    return g_retry_metrics_enabled;
}

void wc_net_set_selftest_fail_first(int enabled) {
    g_selftest_fail_first_once = enabled ? 1 : 0;
}

void wc_net_set_retry_scope_all_addrs(int enabled) {
    g_retry_all_addrs = enabled ? 1 : 0;
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
    if (idle_timeout_ms <= 0) idle_timeout_ms = 2000; // sane default
    if (max_bytes <= 0) max_bytes = 65536;

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
