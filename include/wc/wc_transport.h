#ifndef WC_TRANSPORT_H
#define WC_TRANSPORT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wc_transport {
    int* fd;
} wc_transport_t;

void wc_transport_init(wc_transport_t* transport, int* fd);
int wc_transport_send_all(wc_transport_t* transport, const char* data, size_t len, int timeout_ms);
int wc_transport_recv_until_idle(wc_transport_t* transport, char** out, size_t* out_len, int timeout_ms, int max_bytes);
void wc_transport_close(wc_transport_t* transport, const char* reason, int debug_enabled);

#ifdef __cplusplus
}
#endif

#endif // WC_TRANSPORT_H
