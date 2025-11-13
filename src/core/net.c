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
#include <time.h>
#include <limits.h>

// ---------------------------------------------------------------------------
// Retry pacing & metrics (Phase 1: instrumentation-only, no behavioral change
// unless explicitly enabled via environment variable switches)
// ---------------------------------------------------------------------------
// Environment variables (opt-in):
//   WHOIS_RETRY_METRICS=1        -> enable connect attempt latency collection & summary
//   WHOIS_RETRY_INTERVAL_MS=<n>  -> override base sleep between attempts (disabled by default)
//   WHOIS_RETRY_JITTER_MS=<n>    -> override random jitter 0..n ms (disabled by default)
// Behavior (default): remains single-pass connect over resolved addrinfo list.
// When WHOIS_RETRY_INTERVAL_MS is set (>0), an additional pacing sleep is inserted
// AFTER a failed attempt (only when more addresses remain). This allows us to
// experiment with pacing without changing default code paths.

static int g_retry_metrics_enabled = 0;
static unsigned g_retry_attempts = 0;          // total connect() calls attempted
static unsigned g_retry_successes = 0;         // successful connect() calls
static unsigned g_retry_failures = 0;          // failed connect() calls
static unsigned g_retry_total_sleep_ms = 0;    // total artificial sleep inserted
static unsigned g_latency_count = 0;           // number of recorded latencies
// Use macro for compile-time constant size (C does not treat const unsigned as VLA-safe constant)
#define LAT_CAP 256
static unsigned g_latency_ms[LAT_CAP];         // per-attempt latencies (ms)

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
}

static void wc_net_retry_metrics_init_once(void){
    if (g_retry_metrics_enabled) return;
    const char* m = getenv("WHOIS_RETRY_METRICS");
    if (m && strcmp(m,"1")==0){ g_retry_metrics_enabled = 1; }
    if (g_retry_metrics_enabled){ atexit(wc_net_retry_metrics_flush); }
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
    const char* b = getenv("WHOIS_RETRY_INTERVAL_MS");
    if(!b) return; // pacing disabled unless explicitly requested
    int base = atoi(b); if(base <= 0) return;
    int jitter = 0; const char* j = getenv("WHOIS_RETRY_JITTER_MS"); if(j){ int ji=atoi(j); if(ji>0) jitter = rand() % (ji+1); }
    int sleep_ms = base + jitter;
    struct timespec ts; ts.tv_sec = sleep_ms/1000; ts.tv_nsec = (sleep_ms%1000)*1000000L;
    nanosleep(&ts,NULL);
    g_retry_total_sleep_ms += (unsigned)sleep_ms;
}


static void wc_net_info_init(struct wc_net_info* n){ if(n){ n->fd=-1; n->ip[0]='\0'; n->connected=0; n->err=WC_ERR_INTERNAL; }}

int wc_dial_43(const char* host, uint16_t port, int timeout_ms, int retries, struct wc_net_info* out) {
    // Phase 1: blocking connect; instrumentation & optional pacing inserted.
    wc_net_retry_metrics_init_once();
    if (!host || !out) return WC_ERR_INVALID;
    (void)timeout_ms; // currently unused; kept for future non-blocking dial
    wc_net_info_init(out);
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%u", (unsigned)port);
    struct addrinfo hints; memset(&hints,0,sizeof(hints)); hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC; hints.ai_flags=0;
    struct addrinfo* res = NULL;
    int gerr = getaddrinfo(host, portbuf, &hints, &res);
    if (gerr != 0) {
        out->err = WC_ERR_IO; return out->err;
    }
    int fd = -1; struct addrinfo* rp; int attempt=0; int success=0;
    // Retry loop (instrumentation only; pacing optional via env)
    while(attempt < (retries < 1 ? 1 : retries)) {
        for (rp = res; rp; rp = rp->ai_next) {
            struct timespec t0; if(g_retry_metrics_enabled) clock_gettime(CLOCK_MONOTONIC,&t0);
            g_retry_attempts++;
            fd = (int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd < 0){ g_retry_failures++; continue; }
            if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
                wc_net_record_latency(t0);
                g_retry_successes++;
                if (g_retry_metrics_enabled && g_latency_count > 0) {
                    unsigned last = g_latency_ms[g_latency_count - 1];
                    fprintf(stderr,
                        "[RETRY-METRICS-INSTANT] attempt=%u success=1 latency_ms=%u total_attempts=%u\n",
                        g_retry_attempts, last, g_retry_attempts);
                }
                out->fd = fd; out->connected = 1; out->err = WC_OK;
                char hostbuf[NI_MAXHOST];
                if (getnameinfo(rp->ai_addr, rp->ai_addrlen, hostbuf, sizeof(hostbuf), NULL, 0, NI_NUMERICHOST)==0) {
                    strncpy(out->ip, hostbuf, sizeof(out->ip)-1); out->ip[sizeof(out->ip)-1]='\0';
                } else {
                    strncpy(out->ip, "unknown", sizeof(out->ip)-1);
                }
                success=1; break;
            } else {
                wc_net_record_latency(t0);
                g_retry_failures++;
                close(fd); fd=-1;
            }
        }
        if(success) break;
        wc_net_sleep_between_attempts_if_enabled(attempt, retries);
        attempt++;
    }
    freeaddrinfo(res);
    if (!out->connected) { out->err = WC_ERR_IO; }
    return out->err;
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
