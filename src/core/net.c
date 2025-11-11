// SPDX-License-Identifier: MIT
// net.c - Phase A skeleton implementations for network helpers
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "wc/wc_net.h"

static void wc_net_info_init(struct wc_net_info* n){ if(n){ n->fd=-1; n->ip[0]='\0'; n->connected=0; n->err=WC_ERR_INTERNAL; }}

int wc_dial_43(const char* host, uint16_t port, int timeout_ms, int retries, struct wc_net_info* out) {
    (void)timeout_ms; (void)retries; // placeholders for future non-blocking logic
    if (!host || !out) return WC_ERR_INVALID;
    wc_net_info_init(out);
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%u", (unsigned)port);
    struct addrinfo hints; memset(&hints,0,sizeof(hints)); hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
    struct addrinfo* res = NULL;
    int gerr = getaddrinfo(host, portbuf, &hints, &res);
    if (gerr != 0) {
        out->err = WC_ERR_IO; return out->err;
    }
    int fd = -1; struct addrinfo* rp;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = (int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            out->fd = fd; out->connected = 1; out->err = WC_OK;
            // best-effort human-readable ip
            char hostbuf[NI_MAXHOST];
            if (getnameinfo(rp->ai_addr, rp->ai_addrlen, hostbuf, sizeof(hostbuf), NULL, 0, NI_NUMERICHOST)==0) {
                strncpy(out->ip, hostbuf, sizeof(out->ip)-1); out->ip[sizeof(out->ip)-1]='\0';
            } else {
                strncpy(out->ip, "unknown", sizeof(out->ip)-1);
            }
            break;
        }
        close(fd); fd = -1;
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
    (void)idle_timeout_ms; // placeholder for future idle logic
    if (!out_buf || !out_len) return -1;
    const size_t cap = (size_t) (max_bytes > 0 ? max_bytes : 65536);
    char* buf = (char*)malloc(cap+1); if(!buf) return -1;
    ssize_t r = recv(fd, buf, cap, 0);
    if (r < 0) { free(buf); return -1; }
    buf[r] = '\0';
    *out_buf = buf; *out_len = (size_t)r;
    return r;
}
