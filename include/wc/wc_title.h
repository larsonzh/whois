// SPDX-License-Identifier: MIT
#ifndef WC_TITLE_H
#define WC_TITLE_H

#ifdef __cplusplus
extern "C" {
#endif

// Title projection ("-g") API. Maintains internal patterns state.

// Enable or disable title projection.
void wc_title_set_enabled(int enabled);
int wc_title_is_enabled(void);

// Parse and set patterns separated by '|'. Returns count on success, -1 on error.
int wc_title_parse_patterns(const char* arg);

// Free all allocated resources and disable the feature.
void wc_title_free(void);

// Filter response by title patterns.
//  - wc_title_filter_response_wb writes into caller-provided work buffer and returns a pointer to it.
//  - wc_title_filter_response preserves legacy semantics (malloc result owned by caller).
struct wc_workbuf_t; // fwd decl to avoid header coupling
char* wc_title_filter_response_wb(const char* input, struct wc_workbuf_t* wb);
char* wc_title_filter_response(const char* input);

#ifdef __cplusplus
}
#endif

#endif // WC_TITLE_H
