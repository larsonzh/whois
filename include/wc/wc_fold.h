// SPDX-License-Identifier: MIT
#ifndef WC_FOLD_H
#define WC_FOLD_H

#ifdef __cplusplus
extern "C" {
#endif

// Build a single-line folded summary. The returned string is newline-terminated.
// Parameters:
//  - body: filtered response body (may be NULL)
//  - query: original query; if NULL/empty or likely a regex, the function
//           will try to extract it from header markers in body
//  - rir:   trailing RIR token (use "unknown" when NULL/empty)
//  - sep:   token separator (use " " when NULL)
//  - upper: non-zero to convert tokens/RIR to upper case
//  - wb:    optional work buffer to reuse allocations; if NULL, legacy heap alloc is used
struct wc_workbuf_t; // fwd decl
char* wc_fold_build_line_wb(const char* body,
                            const char* query,
                            const char* rir,
                            const char* sep,
                            int upper,
                            struct wc_workbuf_t* wb);
char* wc_fold_build_line(const char* body,
                         const char* query,
                         const char* rir,
                         const char* sep,
                         int upper);

// Enable/disable unique token behavior in folded output (excludes the first token
// <query> and the last token <RIR>). When enabled, duplicate tokens are removed and
// remaining tokens (except QUERY and RIR) are stably de-duplicated preserving order.
void wc_fold_set_unique(int on);

#ifdef __cplusplus
}
#endif

#endif // WC_FOLD_H
