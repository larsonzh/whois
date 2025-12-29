// SPDX-License-Identifier: MIT
// Core utility helpers shared by whois_client and core modules.

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#endif

#include "wc/wc_output.h"
#include "wc/wc_util.h"

void* wc_safe_malloc(size_t size, const char* function_name)
{
    if (size == 0)
        return NULL;
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr,
            "Error: Memory allocation failed in %s for %zu bytes\n",
            function_name, size);
        exit(EXIT_FAILURE);
    }
    return ptr;
}

char* wc_safe_strdup(const char* s, const char* function_name)
{
    if (!s)
        return NULL;
    size_t len = strlen(s) + 1; // include NUL
    char* p = (char*)wc_safe_malloc(len, function_name);
    memcpy(p, s, len);
    return p;
}

void wc_safe_close(int* fd, const char* function_name, int debug_enabled)
{
    if (!fd || *fd == -1)
        return;

#ifdef _WIN32
    int rc = closesocket((SOCKET)*fd);
    int err = WSAGetLastError();
    if (rc == SOCKET_ERROR) {
        if (err != WSAENOTSOCK && debug_enabled) {
            wc_output_log_message("WARN",
                "%s: Failed to close fd %d: wsa_error=%d",
                function_name, *fd, err);
        }
    } else if (debug_enabled) {
        wc_output_log_message("DEBUG",
            "%s: Closed fd %d",
            function_name, *fd);
    }
#else
    if (close(*fd) == -1) {
        if (errno != EBADF && debug_enabled) {
            wc_output_log_message("WARN",
                "%s: Failed to close fd %d: %s",
                function_name, *fd, strerror(errno));
        }
    } else if (debug_enabled) {
        wc_output_log_message("DEBUG",
            "%s: Closed fd %d",
            function_name, *fd);
    }
#endif

    *fd = -1;
}
