// wc_net.h - Non-blocking TCP connect & basic send/receive helpers (placeholder skeleton for phase A)
#ifndef WC_NET_H_
#define WC_NET_H_

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h> // for ssize_t on some platforms
#include "wc/wc_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Connection result metadata
struct wc_net_info {
    int fd;                 // socket fd (>=0) or -1
    char ip[64];            // resolved remote IP (text) or "unknown"
    int connected;          // 1 if connected, 0 otherwise
    int err;                // wc_err_t mapped error code
    int last_errno;         // last errno from connect/select failure (0 if success)
};

// Convenience helpers that wrap dialing + active-connection registration for
// signal handling. These do not change dialing semantics; they only ensure
// that the currently active socket is visible to wc_signal so that Ctrl-C
// can safely close it.

// Dial whois server on given host:port and, on success, register the socket
// as the current active connection for signal handling. The semantics are the
// same as calling wc_dial_43() followed by wc_signal_register_active_connection().
// The caller owns the returned fd and must close it (typically via
// wc_net_close_and_unregister()).
int wc_net_dial_and_register(const char* host,
                             uint16_t port,
                             int timeout_ms,
                             int retries,
                             struct wc_net_info* out);

// Close the given socket (if *fd >= 0) and unregister it from the
// active-connection tracker used by signal handling. After this call,
// *fd will be set to -1.
void wc_net_close_and_unregister(int* fd);

// Dial whois (TCP) server on given host:port (port usually 43). Non-blocking attempt with
// simplified timeout + retry loop. For phase A skeleton: always blocking, minimal implementation.
// Return WC_OK (0) on success, else mapped error. out->fd >=0 if success.
int wc_dial_43(const char* host, uint16_t port, int timeout_ms, int retries, struct wc_net_info* out);

// Send all bytes (simplified). Returns number of bytes sent or -1 on failure.
ssize_t wc_send_all(int fd, const void* buf, size_t len, int timeout_ms);

// Receive until idle (timeout without new data) or max_bytes reached. Appends to dynamic buffer.
// For skeleton: implementation may just read once. Returns total bytes read or -1 on failure.
ssize_t wc_recv_until_idle(int fd, char** out_buf, size_t* out_len, int idle_timeout_ms, int max_bytes);

// Runtime configuration (release-friendly, no environment dependency)
// Set connect-level pacing configuration. Pass negative values to keep current defaults.
void wc_net_set_pacing_config(int disable,
                              int interval_ms,
                              int jitter_ms,
                              int backoff_factor,
                              int max_ms);

// Enable/disable retry metrics (prints [RETRY-METRICS*] to stderr and registers atexit flush)
void wc_net_set_retry_metrics_enabled(int enabled);
int wc_net_retry_metrics_enabled(void);

// Selftest helper: make first overall attempt fail once (for pacing A/B), disabled by default
void wc_net_set_selftest_fail_first(int enabled);

// Control retry scope: when enabled, apply retry count to every resolved
// address candidate; when disabled (default), only the first address gets
// multiple retries and subsequent addresses are tried once.
void wc_net_set_retry_scope_all_addrs(int enabled);

#ifdef __cplusplus
}
#endif

#endif // WC_NET_H_
