// SPDX-License-Identifier: MIT
#ifndef WC_WORKBUF_H
#define WC_WORKBUF_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Lightweight expandable buffer shared across pipeline stages.
typedef struct wc_workbuf_t {
    char* data;
    size_t cap;
} wc_workbuf_t;

// Initialize / release
static inline void wc_workbuf_init(wc_workbuf_t* wb) {
    if (wb) { wb->data = NULL; wb->cap = 0; }
}

void wc_workbuf_free(wc_workbuf_t* wb);

// Ensure capacity >= need+1 (for NUL). Returns pointer to wb->data.
char* wc_workbuf_reserve(wc_workbuf_t* wb, size_t need, const char* where);

// Copy a C-string into the buffer (including NUL). Returns pointer to wb->data.
char* wc_workbuf_copy_cstr(wc_workbuf_t* wb, const char* src, const char* where);

// Adopt an owned malloc buffer by copying into workbuf, then freeing the source.
char* wc_workbuf_adopt_dup(wc_workbuf_t* wb, char* src_owned, const char* where);

#ifdef __cplusplus
}
#endif

#endif // WC_WORKBUF_H
