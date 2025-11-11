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
};

// Dial whois (TCP) server on given host:port (port usually 43). Non-blocking attempt with
// simplified timeout + retry loop. For phase A skeleton: always blocking, minimal implementation.
// Return WC_OK (0) on success, else mapped error. out->fd >=0 if success.
int wc_dial_43(const char* host, uint16_t port, int timeout_ms, int retries, struct wc_net_info* out);

// Send all bytes (simplified). Returns number of bytes sent or -1 on failure.
ssize_t wc_send_all(int fd, const void* buf, size_t len, int timeout_ms);

// Receive until idle (timeout without new data) or max_bytes reached. Appends to dynamic buffer.
// For skeleton: implementation may just read once. Returns total bytes read or -1 on failure.
ssize_t wc_recv_until_idle(int fd, char** out_buf, size_t* out_len, int idle_timeout_ms, int max_bytes);

#ifdef __cplusplus
}
#endif

#endif // WC_NET_H_
