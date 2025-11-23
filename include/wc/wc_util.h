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

// strdup variant with fatal-on-OOM semantics. Returns NULL only when
// input is NULL; otherwise either succeeds or terminates the process.
char* wc_safe_strdup(const char* s, const char* function_name);

// Safe close wrapper shared by multiple modules; suppresses EBADF noise
// and logs only when useful while always invalidating the descriptor.
void wc_safe_close(int* fd, const char* function_name);

#ifdef __cplusplus
}
#endif

#endif // WC_UTIL_H
