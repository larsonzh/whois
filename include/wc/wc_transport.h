#ifndef WC_TRANSPORT_H
#define WC_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wc_transport {
    const struct wc_transport_ops* ops;
    void* context;
    int* fd;
} wc_transport_t;

enum {
    WC_TRANSPORT_WAIT_READ = 1,
    WC_TRANSPORT_WAIT_WRITE = 2
};

typedef struct wc_transport_ops {
    int (*read)(void* context, char* buffer, size_t length);
    int (*write)(void* context, const char* data, size_t length);
    int (*wait)(void* context, int events, uint64_t deadline_ms);
    void (*close)(void* context, const char* reason, int debug_enabled);
} wc_transport_ops_t;

void wc_transport_init(wc_transport_t* transport, int* fd);
void wc_transport_init_with_ops(wc_transport_t* transport, const wc_transport_ops_t* ops, void* context);
uint64_t wc_transport_deadline_after(int timeout_ms);
int wc_transport_wait_until(wc_transport_t* transport, int events, uint64_t deadline_ms);
int wc_transport_read(wc_transport_t* transport, char* buffer, size_t length);
int wc_transport_write(wc_transport_t* transport, const char* data, size_t length);
int wc_transport_send_all_until(wc_transport_t* transport, const char* data, size_t len, uint64_t deadline_ms);
int wc_transport_send_all(wc_transport_t* transport, const char* data, size_t len, int timeout_ms);
int wc_transport_recv_until_idle(wc_transport_t* transport, char** out, size_t* out_len, int timeout_ms, int max_bytes);
void wc_transport_close(wc_transport_t* transport, const char* reason, int debug_enabled);

#ifdef __cplusplus
}
#endif

#endif // WC_TRANSPORT_H
