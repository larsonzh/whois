// SPDX-License-Identifier: MIT
// transport.c - Byte transport abstraction for lookup I/O

#ifndef __has_include
#define __has_include(x) 0
#endif
#if __has_include("wc/wc_transport.h")
#include "wc/wc_transport.h"
#else
#include <stddef.h>
typedef struct wc_transport {
    int* fd;
} wc_transport_t;
#endif

#include "wc/wc_net.h"
#include "wc/wc_util.h"

void wc_transport_init(wc_transport_t* transport, int* fd)
{
    if (!transport) return;
    transport->fd = fd;
}

static int wc_transport_is_valid(const wc_transport_t* transport)
{
    return transport && transport->fd;
}

int wc_transport_send_all(wc_transport_t* transport, const char* data, size_t len, int timeout_ms)
{
    if (!wc_transport_is_valid(transport)) return -1;
    return wc_send_all(*transport->fd, data, len, timeout_ms);
}

int wc_transport_recv_until_idle(wc_transport_t* transport, char** out, size_t* out_len, int timeout_ms, int max_bytes)
{
    if (!wc_transport_is_valid(transport)) return -1;
    return wc_recv_until_idle(*transport->fd, out, out_len, timeout_ms, max_bytes);
}

void wc_transport_close(wc_transport_t* transport, const char* reason, int debug_enabled)
{
    if (!wc_transport_is_valid(transport)) return;
    wc_safe_close(transport->fd, reason, debug_enabled);
}
