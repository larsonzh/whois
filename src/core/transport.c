// SPDX-License-Identifier: MIT
// transport.c - Byte transport abstraction for lookup I/O

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "wc/wc_transport.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <time.h>
#if defined(_WIN32) || defined(__MINGW32__)
#include <winsock2.h>
#include <windows.h>
#define WC_TRANSPORT_NATIVE_SOCKET(fd) ((SOCKET)(fd))
#else
#include <sys/select.h>
#include <sys/socket.h>
#define WC_TRANSPORT_NATIVE_SOCKET(fd) (fd)
#endif

#include "wc/wc_net.h"
#include "wc/wc_signal.h"
#include "wc/wc_util.h"

static int wc_transport_bare_read(void* context, char* buffer, size_t length)
{
    int* fd = (int*)context;
    if (!fd || *fd < 0) return -1;
    if (length > (size_t)INT_MAX) length = (size_t)INT_MAX;
    return (int)recv(*fd, buffer, (int)length, 0);
}

static int wc_transport_bare_write(void* context, const char* data, size_t length)
{
    int* fd = (int*)context;
    if (!fd || *fd < 0) return -1;
    if (length > (size_t)INT_MAX) length = (size_t)INT_MAX;
    return (int)send(*fd, data, (int)length, 0);
}

static uint64_t wc_transport_now_ms(void)
{
#if defined(_WIN32) || defined(__MINGW32__)
    return (uint64_t)GetTickCount64();
#else
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
#endif
}

uint64_t wc_transport_deadline_after(int timeout_ms)
{
    uint64_t now = wc_transport_now_ms();
    if (timeout_ms <= 0) return now;
    return now + (uint64_t)timeout_ms;
}

static int wc_transport_deadline_remaining(uint64_t deadline_ms)
{
    uint64_t now = wc_transport_now_ms();
    uint64_t remaining;
    if (now >= deadline_ms) return 0;
    remaining = deadline_ms - now;
    return remaining > (uint64_t)INT_MAX ? INT_MAX : (int)remaining;
}

static int wc_transport_bare_wait(void* context, int events, uint64_t deadline_ms)
{
    int* fd = (int*)context;
    fd_set read_fds;
    fd_set write_fds;
    struct timeval timeout;
    int timeout_ms;
    if (!fd || *fd < 0) return -1;
    timeout_ms = wc_transport_deadline_remaining(deadline_ms);
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    if (events & WC_TRANSPORT_WAIT_READ) FD_SET(WC_TRANSPORT_NATIVE_SOCKET(*fd), &read_fds);
    if (events & WC_TRANSPORT_WAIT_WRITE) FD_SET(WC_TRANSPORT_NATIVE_SOCKET(*fd), &write_fds);
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;
    return select(*fd + 1,
                  (events & WC_TRANSPORT_WAIT_READ) ? &read_fds : NULL,
                  (events & WC_TRANSPORT_WAIT_WRITE) ? &write_fds : NULL,
                  NULL,
                  &timeout);
}

static void wc_transport_bare_close(void* context, const char* reason, int debug_enabled)
{
    wc_safe_close((int*)context, reason, debug_enabled);
}

static const wc_transport_ops_t g_wc_transport_bare_ops = {
    wc_transport_bare_read,
    wc_transport_bare_write,
    wc_transport_bare_wait,
    wc_transport_bare_close
};

void wc_transport_init(wc_transport_t* transport, int* fd)
{
    if (!transport) return;
    transport->ops = &g_wc_transport_bare_ops;
    transport->context = fd;
    transport->fd = fd;
}

void wc_transport_init_with_ops(wc_transport_t* transport, const wc_transport_ops_t* ops, void* context)
{
    if (!transport) return;
    transport->ops = ops;
    transport->context = context;
    transport->fd = NULL;
}

static int wc_transport_is_valid(const wc_transport_t* transport)
{
    return transport && transport->ops && transport->context &&
        transport->ops->read && transport->ops->write &&
        transport->ops->wait && transport->ops->close;
}

int wc_transport_wait_until(wc_transport_t* transport, int events, uint64_t deadline_ms)
{
    if (!wc_transport_is_valid(transport) ||
        (events & ~(WC_TRANSPORT_WAIT_READ | WC_TRANSPORT_WAIT_WRITE)) != 0 || events == 0) return -1;
    if (wc_transport_now_ms() >= deadline_ms) return 0;
    return transport->ops->wait(transport->context, events, deadline_ms);
}

int wc_transport_read(wc_transport_t* transport, char* buffer, size_t length)
{
    if (!wc_transport_is_valid(transport) || (!buffer && length != 0)) return -1;
    return transport->ops->read(transport->context, buffer, length);
}

int wc_transport_write(wc_transport_t* transport, const char* data, size_t length)
{
    if (!wc_transport_is_valid(transport) || (!data && length != 0)) return -1;
    return transport->ops->write(transport->context, data, length);
}

int wc_transport_send_all_until(wc_transport_t* transport, const char* data, size_t len, uint64_t deadline_ms)
{
    size_t sent = 0;
    if (!wc_transport_is_valid(transport) || (!data && len != 0)) return -1;
    while (sent < len) {
        int ready = wc_transport_wait_until(transport, WC_TRANSPORT_WAIT_WRITE, deadline_ms);
        if (ready <= 0) return -1;
        int written = wc_transport_write(transport, data + sent, len - sent);
        if (written < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (written == 0) return -1;
        sent += (size_t)written;
    }
    return sent > (size_t)INT_MAX ? INT_MAX : (int)sent;
}

int wc_transport_send_all(wc_transport_t* transport, const char* data, size_t len, int timeout_ms)
{
    if (timeout_ms <= 0) return -1;
    return wc_transport_send_all_until(transport, data, len, wc_transport_deadline_after(timeout_ms));
}

int wc_transport_recv_until_idle(wc_transport_t* transport, char** out, size_t* out_len, int timeout_ms, int max_bytes)
{
    size_t used = 0;
    size_t capacity;
    char* buffer;
    if (!wc_transport_is_valid(transport) || !out || !out_len || timeout_ms <= 0 || max_bytes <= 0) return -1;
    capacity = (size_t)max_bytes;
    buffer = (char*)malloc(capacity + 1);
    if (!buffer) return -1;
    while (used < capacity) {
        if (wc_signal_should_terminate()) {
            errno = EINTR;
            free(buffer);
            return -1;
        }
        uint64_t idle_deadline = wc_transport_deadline_after(timeout_ms);
        int ready = wc_transport_wait_until(transport, WC_TRANSPORT_WAIT_READ, idle_deadline);
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ready == 0) break;
        int received = wc_transport_read(transport, buffer + used, capacity - used);
        if (received < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (received == 0) break;
        used += (size_t)received;
    }
    buffer[used] = '\0';
    *out = buffer;
    *out_len = used;
    return used > (size_t)INT_MAX ? INT_MAX : (int)used;
}

void wc_transport_close(wc_transport_t* transport, const char* reason, int debug_enabled)
{
    if (!wc_transport_is_valid(transport)) return;
    transport->ops->close(transport->context, reason, debug_enabled);
}
