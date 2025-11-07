// SPDX-License-Identifier: MIT
#ifndef WC_GREP_H
#define WC_GREP_H

// Regex-based conditional output filtering
// - POSIX ERE backend
// - Supports block mode (header + continuation) and line mode

#ifdef __cplusplus
extern "C" {
#endif

// Enable/disable module
void wc_grep_set_enabled(int enabled);
int  wc_grep_is_enabled(void);

// Configure pattern and options
// return: 1 on success, 0 if disabled/empty, -1 on error (invalid regex / OOM)
int  wc_grep_compile(const char* pattern, int case_sensitive);
void wc_grep_set_line_mode(int enable);
void wc_grep_set_keep_continuation(int enable);

// Filtering entrypoints
// Caller owns the returned buffer (malloc-allocated)
char* wc_grep_filter(const char* input);      // auto-select by current mode
char* wc_grep_filter_block(const char* input);
char* wc_grep_filter_line(const char* input);

// Cleanup
void wc_grep_free(void);

#ifdef __cplusplus
}
#endif

#endif // WC_GREP_H
