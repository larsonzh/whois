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

// Monotonic view on top of a parent workbuf. The view tracks an offset and a
// cursor; callers advance via wc_workbuf_view_alloc() and can reset via
// wc_workbuf_view_reset(). Capacity is grown on the parent.
typedef struct wc_workbuf_view_t {
    wc_workbuf_t* parent;
    size_t offset;
    size_t cursor;
} wc_workbuf_view_t;

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

// Initialize a monotonic view from parent starting at offset. Cursor starts at 0.
static inline void wc_workbuf_view_init(wc_workbuf_view_t* view, wc_workbuf_t* parent, size_t offset) {
    if (view) { view->parent = parent; view->offset = offset; view->cursor = 0; }
}

// Allocate 'need' bytes from the view, growing the parent as required. Returns
// pointer to the newly allocated region (not NUL-terminated). Cursor advances by need.
char* wc_workbuf_view_alloc(wc_workbuf_view_t* view, size_t need, const char* where);

// Reset the view cursor to zero (does not shrink parent).
static inline void wc_workbuf_view_reset(wc_workbuf_view_t* view) { if (view) view->cursor = 0; }

// Current size of the view (bytes advanced).
static inline size_t wc_workbuf_view_size(const wc_workbuf_view_t* view) { return view ? view->cursor : 0; }

#ifdef __cplusplus
}
#endif

#endif // WC_WORKBUF_H
