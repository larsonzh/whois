// SPDX-License-Identifier: MIT
#ifndef WC_PICK_H_
#define WC_PICK_H_

#ifdef __cplusplus
extern "C" {
#endif

enum wc_pick_mode {
    WC_PICK_MODE_FIRST = 0,
    WC_PICK_MODE_JOIN = 1
};

// Validate, deduplicate, and canonicalize a comma-separated key list.
// The caller owns *canonical_out on success.
int wc_pick_parse_keys(const char* arg, char** canonical_out);

// Build one TAB-separated k=v line from a title/grep-filtered response view.
// The caller owns the returned string.
char* wc_pick_build_line(const char* filtered_view,
                         const char* canonical_keys,
                         enum wc_pick_mode mode);

#ifdef __cplusplus
}
#endif

#endif // WC_PICK_H_