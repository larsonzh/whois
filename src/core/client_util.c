// SPDX-License-Identifier: GPL-3.0-or-later
// Client-side utility helpers for whois CLI layer.

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "wc/wc_client_util.h"
#include "wc/wc_debug.h"

size_t wc_client_parse_size_with_unit(const char* str)
{
    if (str == NULL || *str == '\0') {
        return 0;
    }

    // Skip leading whitespace
    while (isspace((unsigned char)*str)) str++;

    if (*str == '\0') {
        return 0;
    }

    char* end;
    errno = 0;
    unsigned long long size = strtoull(str, &end, 10);
    // Check for conversion errors
    if (errno == ERANGE) {
        return SIZE_MAX;
    }

    if (end == str) {
        return 0;  // Invalid number
    }

    // Skip whitespace after number
    while (isspace((unsigned char)*end)) end++;

    // Process units
    if (*end) {
        char unit = (char)toupper((unsigned char)*end);
        switch (unit) {
        case 'K':
            if (size > SIZE_MAX / 1024) return SIZE_MAX;
            size *= 1024;
            end++;
            break;
        case 'M':
            if (size > SIZE_MAX / (1024ULL * 1024ULL)) return SIZE_MAX;
            size *= 1024ULL * 1024ULL;
            end++;
            break;
        case 'G':
            if (size > SIZE_MAX / (1024ULL * 1024ULL * 1024ULL)) return SIZE_MAX;
            size *= 1024ULL * 1024ULL * 1024ULL;
            end++;
            break;
        default:
            // Invalid unit, but may just be a number
            if (wc_is_debug_enabled()) {
                printf("[DEBUG] Unknown unit '%c' in size specification, ignoring\n",
                       unit);
            }
            break;
        }

        // Check for extra characters (like "B" in "10MB")
        if (*end && !isspace((unsigned char)*end)) {
            if (wc_is_debug_enabled()) {
                printf("[DEBUG] Extra characters after unit: '%s'\n", end);
            }
        }
    }

    // Check if it exceeds size_t maximum value
    if (size > SIZE_MAX) {
        return SIZE_MAX;
    }

    if (wc_is_debug_enabled()) {
        printf("[DEBUG] Parsed size: '%s' -> %llu bytes\n", str, size);
    }

    return (size_t)size;
}
