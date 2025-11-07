// SPDX-License-Identifier: MIT
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <regex.h>
#include "wc/wc_grep.h"

typedef struct {
    int enabled;
    int case_sensitive;
    char* raw;
    regex_t re;
    int compiled;
    int mode_line;        // 1: line mode; 0: block mode
    int keep_cont;        // in line mode: include continuation lines of matched block
} wc_grep_state_t;

static wc_grep_state_t s_grep = {0,0,NULL,{0},0,0,0};

static void* xmalloc(size_t n, const char* where) {
    if (n == 0) n = 1;
    void* p = malloc(n);
    if (!p) { fprintf(stderr, "OOM in %s (%zu bytes)\n", where, (size_t)n); exit(EXIT_FAILURE); }
    return p;
}

static void* xrealloc(void* ptr, size_t n, const char* where) {
    if (n == 0) n = 1;
    void* p = realloc(ptr, n);
    if (!p) { fprintf(stderr, "OOM(realloc) in %s (%zu bytes)\n", where, (size_t)n); exit(EXIT_FAILURE); }
    return p;
}

static char* str_dup_local(const char* s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char* r = (char*)xmalloc(n + 1, "str_dup_local");
    memcpy(r, s, n);
    r[n] = '\0';
    return r;
}

// Detect header token at line start and whether the line is a continuation.
//  - Return 1 for header lines; name_ptr/name_len_ptr point to the header name (no ':').
//  - leading_ws_ptr indicates if the line starts with whitespace (continuation candidate).
static int is_header_line_and_name_local(const char* line, size_t len,
                                         const char** name_ptr,
                                         size_t* name_len_ptr,
                                         int* leading_ws_ptr) {
    const char* s = line;
    const char* end = line + len;
    int leading_ws = 0;
    if (s < end && (*s == ' ' || *s == '\t')) leading_ws = 1;
    // Header lines in WHOIS must start at column 0 (no leading whitespace).
    // If there's leading whitespace, treat this line as a continuation candidate,
    // never as a header, even if a colon appears later.
    if (leading_ws) {
        // By contract, header fields start at column 0; any leading whitespace means continuation.
        if (leading_ws_ptr) *leading_ws_ptr = leading_ws;
        return 0;
    }
    while (s < end && (*s == ' ' || *s == '\t')) s++;
    const char* tok_start = s;
    while (s < end && *s != ' ' && *s != '\t' && *s != '\r' && *s != '\n') {
        if (*s == ':') break;
        s++;
    }
    if (s < end && *s == ':') {
        const char* name_start = tok_start;
        size_t nlen = (size_t)(s - name_start);
        if (nlen == 0) {
            if (leading_ws_ptr) *leading_ws_ptr = leading_ws;
            return 0;
        }
        if (name_ptr) *name_ptr = name_start;
        if (name_len_ptr) *name_len_ptr = nlen;
        if (leading_ws_ptr) *leading_ws_ptr = leading_ws;
        return 1;
    }
    if (leading_ws_ptr) *leading_ws_ptr = leading_ws;
    return 0;
}

void wc_grep_set_enabled(int enabled) { s_grep.enabled = enabled ? 1 : 0; }
int  wc_grep_is_enabled(void) { return s_grep.enabled && s_grep.compiled; }

int wc_grep_compile(const char* pattern, int case_sensitive) {
    if (!pattern || !*pattern) { s_grep.enabled = 0; return 0; }
    if (strlen(pattern) > 4096) {
        fprintf(stderr, "Error: --grep pattern too long (max 4096)\n");
        return -1;
    }
    // preserve mode toggles across re-compilation
    int prev_mode_line = s_grep.mode_line;
    int prev_keep_cont = s_grep.keep_cont;
    wc_grep_free();
    s_grep.enabled = 1;
    s_grep.case_sensitive = case_sensitive ? 1 : 0;
    s_grep.raw = str_dup_local(pattern);
    if (!s_grep.raw) { fprintf(stderr, "Error: OOM parsing --grep\n"); return -1; }
    int flags = REG_EXTENDED | REG_NOSUB;
    if (!s_grep.case_sensitive) flags |= REG_ICASE;
    int rc = regcomp(&s_grep.re, pattern, flags);
    if (rc != 0) {
        char buf[256];
        regerror(rc, &s_grep.re, buf, sizeof(buf));
        fprintf(stderr, "Error: invalid regex: %s\n", buf);
        wc_grep_free();
        return -1;
    }
    s_grep.compiled = 1;
    s_grep.mode_line = prev_mode_line;
    s_grep.keep_cont = prev_keep_cont;
    return 1;
}

void wc_grep_set_line_mode(int enable) { s_grep.mode_line = enable ? 1 : 0; }
void wc_grep_set_keep_continuation(int enable) { s_grep.keep_cont = enable ? 1 : 0; }

// Block mode filter
char* wc_grep_filter_block(const char* input) {
    if (!wc_grep_is_enabled() || !input) return input ? str_dup_local(input) : str_dup_local("");
    size_t in_len = strlen(input);
    char* out = (char*)xmalloc(in_len + 1, "wc_grep_filter_block");
    size_t opos = 0;

    char* blk = (char*)xmalloc(in_len + 1, "wc_grep_filter_block.blk");
    size_t bpos = 0; int in_block = 0; int blk_matched = 0; int allow_indented_header_like_cont = 0; int cont_count = 0; int global_allow_indented_header_like_cont = 1;

    char* tmp = NULL; size_t tmp_cap = 0;

    const char* p = input;
    while (*p) {
        const char* line_start = p; const char* q = p;
        while (*q && *q != '\n') q++;
        size_t line_len = (size_t)(q - line_start);
        size_t det_len = line_len; if (det_len > 0 && line_start[det_len - 1] == '\r') det_len--;

    const char* hname = NULL; size_t hlen = 0; int leading_ws = 0;
    int is_header = is_header_line_and_name_local(line_start, det_len, &hname, &hlen, &leading_ws);
    int is_cont = (!is_header && leading_ws);  // any indented line is continuation
    int is_boundary = (!is_header && !is_cont);

        if (is_header && in_block) {
            if (blk_matched && bpos > 0) { memcpy(out + opos, blk, bpos); opos += bpos; }
            bpos = 0; blk_matched = 0; in_block = 0;
        }

        if (is_header) {
            in_block = 1;
            allow_indented_header_like_cont = 1; // reset allowance for first indented header-like line
            cont_count = 0; // reset continuation count
            memcpy(blk + bpos, line_start, line_len);
            bpos += line_len; if (*q == '\n') blk[bpos++] = '\n';
            if (!blk_matched && s_grep.compiled) {
                if (det_len > tmp_cap) { size_t nc = det_len + 1; tmp = (char*)xrealloc(tmp, nc, "wc_grep.tmp"); tmp_cap = nc - 1; }
                if (tmp_cap >= det_len) { memcpy(tmp, line_start, det_len); tmp[det_len] = '\0'; if (regexec(&s_grep.re, tmp, 0, NULL, 0) == 0) blk_matched = 1; }
            }
        } else if (is_cont && in_block) {
            // Heuristic: allow at most one indented header-like line (contains ':' after trim) as continuation;
            // subsequent indented header-like lines start a new block (boundary) so they can be filtered separately.
            int header_like = 0;
            {
                const char* ts = line_start;
                const char* te = line_start + det_len;
                while (ts < te && (*ts == ' ' || *ts == '\t')) ts++;
                const char* scan = ts;
                while (scan < te && *scan != ' ' && *scan != '\t' && *scan != '\r' && *scan != '\n') {
                    if (*scan == ':') break;
                    scan++;
                }
                if (scan < te && *scan == ':' && scan > ts) header_like = 1;
            }
            if (header_like && !allow_indented_header_like_cont) {
                // treat as boundary: flush current block if matched, then start new block logic below
                if (blk_matched && bpos > 0) { memcpy(out + opos, blk, bpos); opos += bpos; }
                bpos = 0; blk_matched = 0; in_block = 0;
                // Now process as header (without resetting allowance again since it's indented -> new logical header not matched pattern maybe)
                in_block = 1;
                allow_indented_header_like_cont = 1; // new block allowance
                cont_count = 0;
                memcpy(blk + bpos, line_start, line_len);
                bpos += line_len; if (*q == '\n') blk[bpos++] = '\n';
                if (!blk_matched && s_grep.compiled) {
                    if (det_len > tmp_cap) { size_t nc = det_len + 1; tmp = (char*)xrealloc(tmp, nc, "wc_grep.tmp"); tmp_cap = nc - 1; }
                    if (tmp_cap >= det_len) { memcpy(tmp, line_start, det_len); tmp[det_len] = '\0'; if (regexec(&s_grep.re, tmp, 0, NULL, 0) == 0) blk_matched = 1; }
                }
            } else {
                // continuation appended (with selective filtering):
                // Rule: keep all non header-like continuation lines; keep the first header-like continuation line
                // only once globally across entire input; skip header-like continuation lines that do not match regex otherwise.
                int skip_line = 0;
                if (header_like) {
                    if (allow_indented_header_like_cont) {
                        if (global_allow_indented_header_like_cont) {
                            // allow only once globally
                            allow_indented_header_like_cont = 0;
                            global_allow_indented_header_like_cont = 0;
                        } else {
                            // global allowance exhausted; require regex match to keep
                            int matched_here = 0;
                            if (s_grep.compiled) {
                                if (det_len > tmp_cap) { size_t nc = det_len + 1; tmp = (char*)xrealloc(tmp, nc, "wc_grep.tmp"); tmp_cap = nc - 1; }
                                if (tmp_cap >= det_len) { memcpy(tmp, line_start, det_len); tmp[det_len] = '\0'; if (regexec(&s_grep.re, tmp, 0, NULL, 0) == 0) matched_here = 1; }
                            }
                            if (!matched_here) skip_line = 1; else blk_matched = 1;
                            allow_indented_header_like_cont = 0; // consume per-block allowance regardless
                        }
                    } else {
                        // subsequent header-like continuation: require regex match OR block not yet matched
                        int matched_here = 0;
                        if (s_grep.compiled) {
                            if (det_len > tmp_cap) { size_t nc = det_len + 1; tmp = (char*)xrealloc(tmp, nc, "wc_grep.tmp"); tmp_cap = nc - 1; }
                            if (tmp_cap >= det_len) { memcpy(tmp, line_start, det_len); tmp[det_len] = '\0'; if (regexec(&s_grep.re, tmp, 0, NULL, 0) == 0) matched_here = 1; }
                        }
                        if (!matched_here) skip_line = 1; else blk_matched = 1;
                    }
                }
                if (!skip_line) {
                    memcpy(blk + bpos, line_start, line_len);
                    bpos += line_len; if (*q == '\n') blk[bpos++] = '\n';
                    if (!blk_matched && s_grep.compiled) {
                        if (det_len > tmp_cap) { size_t nc = det_len + 1; tmp = (char*)xrealloc(tmp, nc, "wc_grep.tmp"); tmp_cap = nc - 1; }
                        if (tmp_cap >= det_len) { memcpy(tmp, line_start, det_len); tmp[det_len] = '\0'; if (regexec(&s_grep.re, tmp, 0, NULL, 0) == 0) blk_matched = 1; }
                    }
                    cont_count++;
                }
            }
        } else if (is_boundary) {
            if (in_block) {
                if (blk_matched && bpos > 0) { memcpy(out + opos, blk, bpos); opos += bpos; }
                bpos = 0; blk_matched = 0; in_block = 0;
            }
            // skip boundary lines
        }

        p = (*q == '\n') ? (q + 1) : q;
    }

    if (in_block) {
        if (blk_matched && bpos > 0) { memcpy(out + opos, blk, bpos); opos += bpos; }
    }

    if (tmp) free(tmp);
    free(blk);
    out[opos] = '\0';
    return out;
}

// Line mode filter
char* wc_grep_filter_line(const char* input) {
    if (!wc_grep_is_enabled() || !input) return input ? str_dup_local(input) : str_dup_local("");
    size_t in_len = strlen(input);
    char* out = (char*)xmalloc(in_len + 1, "wc_grep_filter_line");
    size_t opos = 0;

    char* blk = (char*)xmalloc(in_len + 1, "wc_grep_filter_line.blk");
    size_t bpos = 0; int in_block = 0; int blk_matched = 0;
    char* tmp = NULL; size_t tmp_cap = 0;

    const char* p = input;
    while (*p) {
        const char* line_start = p; const char* q = p;
        while (*q && *q != '\n') q++;
        size_t line_len = (size_t)(q - line_start);
        size_t det_len = line_len; if (det_len > 0 && line_start[det_len - 1] == '\r') det_len--;

    const char* hname = NULL; size_t hlen = 0; int leading_ws = 0;
    int is_header = is_header_line_and_name_local(line_start, det_len, &hname, &hlen, &leading_ws);
    int is_cont = (!is_header && leading_ws);  // any indented line is continuation
    int is_boundary = (!is_header && !is_cont);

        if (is_header && in_block) {
            if (s_grep.keep_cont) { if (blk_matched && bpos > 0) { memcpy(out + opos, blk, bpos); opos += bpos; } }
            bpos = 0; blk_matched = 0; in_block = 0;
        }

        if (is_header) {
            in_block = 1;
            memcpy(blk + bpos, line_start, line_len);
            bpos += line_len; if (*q == '\n') blk[bpos++] = '\n';
            if (det_len > tmp_cap) { size_t nc = det_len + 1; tmp = (char*)xrealloc(tmp, nc, "wc_grep.tmp"); tmp_cap = nc - 1; }
            int rc = 1; if (tmp_cap >= det_len) { memcpy(tmp, line_start, det_len); tmp[det_len] = '\0'; rc = regexec(&s_grep.re, tmp, 0, NULL, 0); }
            if (rc == 0) { blk_matched = 1; if (!s_grep.keep_cont) { memcpy(out + opos, line_start, line_len); opos += line_len; if (*q == '\n') out[opos++] = '\n'; } }
        } else if (is_cont && in_block) {
            memcpy(blk + bpos, line_start, line_len);
            bpos += line_len; if (*q == '\n') blk[bpos++] = '\n';
            if (det_len > tmp_cap) { size_t nc = det_len + 1; tmp = (char*)xrealloc(tmp, nc, "wc_grep.tmp"); tmp_cap = nc - 1; }
            int rc = 1; if (tmp_cap >= det_len) { memcpy(tmp, line_start, det_len); tmp[det_len] = '\0'; rc = regexec(&s_grep.re, tmp, 0, NULL, 0); }
            if (rc == 0) { blk_matched = 1; if (!s_grep.keep_cont) { memcpy(out + opos, line_start, line_len); opos += line_len; if (*q == '\n') out[opos++] = '\n'; } }
        } else if (is_boundary) {
            if (in_block) { if (s_grep.keep_cont) { if (blk_matched && bpos > 0) { memcpy(out + opos, blk, bpos); opos += bpos; } } bpos = 0; blk_matched = 0; in_block = 0; }
            // keep markers "=== ..." regardless of match
            if (det_len >= 3 && line_start[0] == '=' && line_start[1] == '=' && line_start[2] == '=') {
                memcpy(out + opos, line_start, line_len); opos += line_len; if (*q == '\n') out[opos++] = '\n';
            } else {
                if (det_len > tmp_cap) { size_t nc = det_len + 1; tmp = (char*)xrealloc(tmp, nc, "wc_grep.tmp"); tmp_cap = nc - 1; }
                int rc = 1; if (tmp_cap >= det_len) { memcpy(tmp, line_start, det_len); tmp[det_len] = '\0'; rc = regexec(&s_grep.re, tmp, 0, NULL, 0); }
                if (rc == 0) { memcpy(out + opos, line_start, line_len); opos += line_len; if (*q == '\n') out[opos++] = '\n'; }
            }
        }

        p = (*q == '\n') ? (q + 1) : q;
    }

    if (in_block) { if (s_grep.keep_cont) { if (blk_matched && bpos > 0) { memcpy(out + opos, blk, bpos); opos += bpos; } } }

    if (tmp) free(tmp);
    free(blk);
    out[opos] = '\0';
    return out;
}

char* wc_grep_filter(const char* input) {
    return s_grep.mode_line ? wc_grep_filter_line(input) : wc_grep_filter_block(input);
}

void wc_grep_free(void) {
    if (s_grep.compiled) { regfree(&s_grep.re); s_grep.compiled = 0; }
    if (s_grep.raw) { free(s_grep.raw); s_grep.raw = NULL; }
    s_grep.enabled = 0; s_grep.case_sensitive = 0; s_grep.mode_line = 0; s_grep.keep_cont = 0;
}
