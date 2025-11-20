// SPDX-License-Identifier: MIT
#ifndef WC_UTIL_H
#define WC_UTIL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Process-wide utility helpers shared across modules.
// Memory allocation with fatal on OOM, mirroring existing safe_malloc behavior.
void* wc_safe_malloc(size_t size, const char* function_name);

#ifdef __cplusplus
}
#endif

#endif // WC_UTIL_H
