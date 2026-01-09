// wc_net.h - Non-blocking TCP helpers with retry pacing/metrics context
#ifndef WC_NET_H_
#define WC_NET_H_

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h> // for ssize_t on some platforms
#include "wc/wc_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WC_NET_LATENCY_CAP 256

struct Config; // forward declaration to avoid heavy include
struct wc_selftest_injection_s; // forward declaration to avoid heavy include

typedef struct wc_net_context_config {
    int pacing_disable;        // 0 keep pacing, 1 disable
    int pacing_interval_ms;    // base delay between retries
    int pacing_jitter_ms;      // random jitter added to pacing interval
    int pacing_backoff_factor; // exponential backoff multiplier
    int pacing_max_ms;         // cap for pacing sleep
    int retry_scope_all_addrs; // apply retry budget to every address candidate
    int retry_metrics_enabled; // emit [RETRY-*] telemetry
    int max_host_addrs;        // cap per-host address attempts from getaddrinfo (0 = unbounded)
    const struct Config* config; // optional injected Config for downstream helpers
    const struct wc_selftest_injection_s* injection; // optional injected selftest baseline
} wc_net_context_config_t;

typedef struct wc_net_probe_result_t {
    int probed; // 1 if probe already executed
    int ipv4_ok;
    int ipv6_ok;
} wc_net_probe_result_t;

typedef struct wc_net_context wc_net_context_t;

struct wc_net_context {
    wc_net_context_config_t cfg;
    unsigned attempts;
    unsigned successes;
    unsigned failures;
    unsigned total_sleep_ms;
    unsigned latency_count;
    unsigned latency_ms[WC_NET_LATENCY_CAP];
    unsigned err_timeout;
    unsigned err_refused;
    unsigned err_net_unreach;
    unsigned err_host_unreach;
    unsigned err_addr_na;
    unsigned err_intr;
    unsigned err_other;
    int selftest_fail_first_once;
    unsigned selftest_fault_version_seen;
    int registered_for_flush;
    struct wc_net_context* next_registered;
    const struct Config* config; // propagated config for dns/backoff helpers
    const struct wc_selftest_injection_s* injection; // propagated selftest baseline
};

void wc_net_context_config_init(wc_net_context_config_t* cfg);
int wc_net_context_init(wc_net_context_t* ctx, const wc_net_context_config_t* cfg);
void wc_net_context_shutdown(wc_net_context_t* ctx);

// One-time probe of IPv4/IPv6 availability. Returns 0 on success and
// fills `out`; subsequent calls return cached results.
int wc_net_probe_families(wc_net_probe_result_t* out);

void wc_net_context_set_active(wc_net_context_t* ctx);
wc_net_context_t* wc_net_context_get_active(void);
int wc_net_register_flush_hook(void);
void wc_net_flush_registered_contexts(void);

int wc_net_context_retry_metrics_enabled(const wc_net_context_t* ctx);
int wc_net_retry_metrics_enabled(void);

// Connection result metadata
struct wc_net_info {
    int fd;                 // socket fd (>=0) or -1
    char ip[64];            // resolved remote IP (text) or "unknown"
    int connected;          // 1 if connected, 0 otherwise
    int err;                // wc_err_t mapped error code
    int last_errno;         // last errno from connect/select failure (0 if success)
};

int wc_net_dial_and_register(wc_net_context_t* ctx,
                             const char* host,
                             uint16_t port,
                             int timeout_ms,
                             int retries,
                             struct wc_net_info* out);

void wc_net_close_and_unregister(int* fd);

int wc_dial_43(wc_net_context_t* ctx,
               const char* host,
               uint16_t port,
               int timeout_ms,
               int retries,
               struct wc_net_info* out);

ssize_t wc_send_all(int fd, const void* buf, size_t len, int timeout_ms);
ssize_t wc_recv_until_idle(int fd, char** out_buf, size_t* out_len, int idle_timeout_ms, int max_bytes);

#ifdef __cplusplus
}
#endif

#endif // WC_NET_H_
