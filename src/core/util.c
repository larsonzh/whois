// SPDX-License-Identifier: MIT
// Core utility helpers shared by whois_client and core modules.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
