// SPDX-License-Identifier: MIT
// Core utility helpers shared by whois_client and core modules.

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wc/wc_runtime.h"
#include "wc/wc_output.h"
#include "wc/wc_util.h"

static int wc_util_debug_enabled(void)
{
    const wc_runtime_cfg_view_t* view = wc_runtime_config_view();
    return view ? view->debug : 0;
}

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

void wc_safe_close(int* fd, const char* function_name)
{
    if (!fd || *fd == -1)
        return;

    if (close(*fd) == -1) {
        if (errno != EBADF && wc_util_debug_enabled()) {
            wc_output_log_message("WARN",
                "%s: Failed to close fd %d: %s",
                function_name, *fd, strerror(errno));
        }
    } else if (wc_util_debug_enabled()) {
        wc_output_log_message("DEBUG",
            "%s: Closed fd %d",
            function_name, *fd);
    }

    *fd = -1;
}
