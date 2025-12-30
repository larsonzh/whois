// SPDX-License-Identifier: MIT
#ifndef WC_HEADER_H
#define WC_HEADER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

// Parsed view of a header/continuation line
typedef struct wc_header_view_s {
    int is_header;      // 1 if line is a header (has name: value)
    int is_cont;        // 1 if line is considered a continuation (leading whitespace and not a header)
    int leading_ws;     // 1 if line starts with space/tab
    const char* name;   // header name (not null-terminated)
    size_t name_len;    // length of header name
} wc_header_view_t;

// Parse a line (without trailing '\n') and fill view.
// allow_indented_header: if non-zero, a header is recognized even when the line starts with whitespace.
// Returns 1 if header detected, 0 otherwise. out may be NULL to probe.
int wc_header_parse(const char* line, size_t len, int allow_indented_header, wc_header_view_t* out);

#ifdef __cplusplus
}
#endif

#endif // WC_HEADER_H
