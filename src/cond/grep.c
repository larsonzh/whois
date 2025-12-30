// SPDX-License-Identifier: MIT
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <regex.h>
#include "wc/wc_grep.h"
#include "wc/wc_workbuf.h"
#include "wc/wc_header.h"

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

static char* str_dup_local(const char* s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char* r = (char*)xmalloc(n + 1, "str_dup_local");
    memcpy(r, s, n);
    r[n] = '\0';
    return r;
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

// Block mode filter (workbuf-backed)
char* wc_grep_filter_block_wb(const char* input, wc_workbuf_t* wb) {
    if (!wc_grep_is_enabled() || !input) return wc_workbuf_copy_cstr(wb, input ? input : "", "wc_grep_filter_block_wb");
    size_t opos = 0;
    size_t bpos = 0; int in_block = 0; int blk_matched = 0; int allow_indented_header_like_cont = 0; int global_allow_indented_header_like_cont = 1;
    wc_workbuf_t blk_wb; wc_workbuf_init(&blk_wb);
    wc_workbuf_t tmp_wb; wc_workbuf_init(&tmp_wb);
    char tmp_stack[4096];
    char* out = wc_workbuf_reserve(wb, 1, "wc_grep_filter_block_wb");
    char* blk = NULL;

    const char* p = input;
    while (*p) {
        const char* line_start = p; const char* q = p;
        while (*q && *q != '\n') q++;
        size_t line_len = (size_t)(q - line_start);
        size_t det_len = line_len; if (det_len > 0 && line_start[det_len - 1] == '\r') det_len--;

        wc_header_view_t hv; memset(&hv, 0, sizeof(hv));
        int is_header = wc_header_parse(line_start, det_len, 0, &hv);
        int is_cont = hv.is_cont;  // any indented line is continuation
        int is_boundary = (!is_header && !is_cont);

        if (is_header && in_block) {
            if (blk_matched && bpos > 0) { out = wc_workbuf_reserve(wb, opos + bpos, "wc_grep_filter_block_flush"); memcpy(out + opos, blk, bpos); opos += bpos; }
            bpos = 0; blk_matched = 0; in_block = 0;
        }

        if (is_header) {
            in_block = 1;
            allow_indented_header_like_cont = 1; // reset allowance for first indented header-like line
            blk = wc_workbuf_reserve(&blk_wb, bpos + line_len, "wc_grep_block_buf");
            memcpy(blk + bpos, line_start, line_len);
            bpos += line_len; if (*q == '\n') { blk = wc_workbuf_reserve(&blk_wb, bpos + 1, "wc_grep_block_buf_nl"); blk[bpos++] = '\n'; }
            if (!blk_matched && s_grep.compiled) {
                const char* tmp = NULL;
                if (det_len < sizeof(tmp_stack)) { memcpy(tmp_stack, line_start, det_len); tmp_stack[det_len] = '\0'; tmp = tmp_stack; }
                else { char* t = wc_workbuf_reserve(&tmp_wb, det_len, "wc_grep_tmp_line"); memcpy(t, line_start, det_len); t[det_len] = '\0'; tmp = t; }
                if (regexec(&s_grep.re, tmp, 0, NULL, 0) == 0) blk_matched = 1;
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
                if (blk_matched && bpos > 0) { out = wc_workbuf_reserve(wb, opos + bpos, "wc_grep_filter_block_flush"); memcpy(out + opos, blk, bpos); opos += bpos; }
                bpos = 0; blk_matched = 0; in_block = 0;
                // Now process as header (without resetting allowance again since it's indented -> new logical header not matched pattern maybe)
                in_block = 1;
                allow_indented_header_like_cont = 1; // new block allowance
                blk = wc_workbuf_reserve(&blk_wb, bpos + line_len, "wc_grep_block_buf");
                memcpy(blk + bpos, line_start, line_len);
                bpos += line_len; if (*q == '\n') { blk = wc_workbuf_reserve(&blk_wb, bpos + 1, "wc_grep_block_buf_nl"); blk[bpos++] = '\n'; }
                if (!blk_matched && s_grep.compiled) {
                    const char* tmp = NULL;
                    if (det_len < sizeof(tmp_stack)) { memcpy(tmp_stack, line_start, det_len); tmp_stack[det_len] = '\0'; tmp = tmp_stack; }
                    else { char* t = wc_workbuf_reserve(&tmp_wb, det_len, "wc_grep_tmp_line"); memcpy(t, line_start, det_len); t[det_len] = '\0'; tmp = t; }
                    if (regexec(&s_grep.re, tmp, 0, NULL, 0) == 0) blk_matched = 1; }
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
                                const char* tmp = NULL;
                                if (det_len < sizeof(tmp_stack)) { memcpy(tmp_stack, line_start, det_len); tmp_stack[det_len] = '\0'; tmp = tmp_stack; }
                                else { char* t = wc_workbuf_reserve(&tmp_wb, det_len, "wc_grep_tmp_line"); memcpy(t, line_start, det_len); t[det_len] = '\0'; tmp = t; }
                                if (regexec(&s_grep.re, tmp, 0, NULL, 0) == 0) matched_here = 1; }
                            if (!matched_here) skip_line = 1; else blk_matched = 1;
                            allow_indented_header_like_cont = 0; // consume per-block allowance regardless
                        }
                    } else {
                        // subsequent header-like continuation: require regex match OR block not yet matched
                        int matched_here = 0;
                        if (s_grep.compiled) {
                            const char* tmp = NULL;
                            if (det_len < sizeof(tmp_stack)) { memcpy(tmp_stack, line_start, det_len); tmp_stack[det_len] = '\0'; tmp = tmp_stack; }
                            else { char* t = wc_workbuf_reserve(&tmp_wb, det_len, "wc_grep_tmp_line"); memcpy(t, line_start, det_len); t[det_len] = '\0'; tmp = t; }
                            if (regexec(&s_grep.re, tmp, 0, NULL, 0) == 0) matched_here = 1; }
                        if (!matched_here) skip_line = 1; else blk_matched = 1;
                    }
                }
                if (!skip_line) {
                    blk = wc_workbuf_reserve(&blk_wb, bpos + line_len, "wc_grep_block_buf");
                    memcpy(blk + bpos, line_start, line_len);
                    bpos += line_len; if (*q == '\n') { blk = wc_workbuf_reserve(&blk_wb, bpos + 1, "wc_grep_block_buf_nl"); blk[bpos++] = '\n'; }
                    if (!blk_matched && s_grep.compiled) {
                        const char* tmp = NULL;
                        if (det_len < sizeof(tmp_stack)) { memcpy(tmp_stack, line_start, det_len); tmp_stack[det_len] = '\0'; tmp = tmp_stack; }
                        else { char* t = wc_workbuf_reserve(&tmp_wb, det_len, "wc_grep_tmp_line"); memcpy(t, line_start, det_len); t[det_len] = '\0'; tmp = t; }
                        if (regexec(&s_grep.re, tmp, 0, NULL, 0) == 0) blk_matched = 1; }
                }
            }
        } else if (is_boundary) {
            if (in_block) {
                if (blk_matched && bpos > 0) { out = wc_workbuf_reserve(wb, opos + bpos, "wc_grep_filter_block_flush"); memcpy(out + opos, blk, bpos); opos += bpos; }
                bpos = 0; blk_matched = 0; in_block = 0;
            }
            // skip boundary lines
        }

        p = (*q == '\n') ? (q + 1) : q;
    }

    if (in_block) {
        if (blk_matched && bpos > 0) { out = wc_workbuf_reserve(wb, opos + bpos, "wc_grep_filter_block_flush"); memcpy(out + opos, blk, bpos); opos += bpos; }
    }

    out = wc_workbuf_reserve(wb, opos + 1, "wc_grep_filter_block_terminate");
    out[opos] = '\0';
    wc_workbuf_free(&blk_wb);
    wc_workbuf_free(&tmp_wb);
    return out;
}

// Line mode filter (workbuf-backed)
char* wc_grep_filter_line_wb(const char* input, wc_workbuf_t* wb) {
    if (!wc_grep_is_enabled() || !input) return wc_workbuf_copy_cstr(wb, input ? input : "", "wc_grep_filter_line_wb");
    size_t in_len = strlen(input);
    size_t chunk = in_len + 1;
    char* base = wc_workbuf_reserve(wb, chunk * 3, "wc_grep_filter_line_wb");
    char* out = base;
    char* blk = base + chunk;
    char* tmp = base + chunk * 2;
    size_t tmp_cap = chunk - 1;
    size_t opos = 0;
    size_t bpos = 0; int in_block = 0; int blk_matched = 0;

    const char* p = input;
    while (*p) {
        const char* line_start = p; const char* q = p;
        while (*q && *q != '\n') q++;
        size_t line_len = (size_t)(q - line_start);
        size_t det_len = line_len; if (det_len > 0 && line_start[det_len - 1] == '\r') det_len--;

        wc_header_view_t hv; memset(&hv, 0, sizeof(hv));
        int is_header = wc_header_parse(line_start, det_len, 0, &hv);
        int is_cont = hv.is_cont;  // any indented line is continuation
        int is_boundary = (!is_header && !is_cont);

        if (is_header && in_block) {
            if (s_grep.keep_cont) { if (blk_matched && bpos > 0) { memcpy(out + opos, blk, bpos); opos += bpos; } }
            bpos = 0; blk_matched = 0; in_block = 0;
        }

        if (is_header) {
            in_block = 1;
            memcpy(blk + bpos, line_start, line_len);
            bpos += line_len; if (*q == '\n') blk[bpos++] = '\n';
            int rc = 1; if (det_len <= tmp_cap) { memcpy(tmp, line_start, det_len); tmp[det_len] = '\0'; rc = regexec(&s_grep.re, tmp, 0, NULL, 0); }
            if (rc == 0) { blk_matched = 1; if (!s_grep.keep_cont) { memcpy(out + opos, line_start, line_len); opos += line_len; if (*q == '\n') out[opos++] = '\n'; } }
        } else if (is_cont && in_block) {
            memcpy(blk + bpos, line_start, line_len);
            bpos += line_len; if (*q == '\n') blk[bpos++] = '\n';
            int rc = 1; if (det_len <= tmp_cap) { memcpy(tmp, line_start, det_len); tmp[det_len] = '\0'; rc = regexec(&s_grep.re, tmp, 0, NULL, 0); }
            if (rc == 0) { blk_matched = 1; if (!s_grep.keep_cont) { memcpy(out + opos, line_start, line_len); opos += line_len; if (*q == '\n') out[opos++] = '\n'; } }
        } else if (is_boundary) {
            if (in_block) { if (s_grep.keep_cont) { if (blk_matched && bpos > 0) { memcpy(out + opos, blk, bpos); opos += bpos; } } bpos = 0; blk_matched = 0; in_block = 0; }
            // keep markers "=== ..." regardless of match
            if (det_len >= 3 && line_start[0] == '=' && line_start[1] == '=' && line_start[2] == '=') {
                memcpy(out + opos, line_start, line_len); opos += line_len; if (*q == '\n') out[opos++] = '\n';
            } else {
                int rc = 1; if (det_len <= tmp_cap) { memcpy(tmp, line_start, det_len); tmp[det_len] = '\0'; rc = regexec(&s_grep.re, tmp, 0, NULL, 0); }
                if (rc == 0) { memcpy(out + opos, line_start, line_len); opos += line_len; if (*q == '\n') out[opos++] = '\n'; }
            }
        }

        p = (*q == '\n') ? (q + 1) : q;
    }

    if (in_block) { if (s_grep.keep_cont) { if (blk_matched && bpos > 0) { memcpy(out + opos, blk, bpos); opos += bpos; } } }

    out[opos] = '\0';
    return out;
}

char* wc_grep_filter_wb(const char* input, wc_workbuf_t* wb) {
    return s_grep.mode_line ? wc_grep_filter_line_wb(input, wb) : wc_grep_filter_block_wb(input, wb);
}

char* wc_grep_filter(const char* input) {
    wc_workbuf_t wb; wc_workbuf_init(&wb);
    char* view = wc_grep_filter_wb(input, &wb);
    size_t len = view ? strlen(view) : 0;
    char* out = (char*)xmalloc(len + 1, "wc_grep_filter");
    if (view) memcpy(out, view, len + 1); else out[0] = '\0';
    wc_workbuf_free(&wb);
    return out;
}

void wc_grep_free(void) {
    if (s_grep.compiled) { regfree(&s_grep.re); s_grep.compiled = 0; }
    if (s_grep.raw) { free(s_grep.raw); s_grep.raw = NULL; }
    s_grep.enabled = 0; s_grep.case_sensitive = 0; s_grep.mode_line = 0; s_grep.keep_cont = 0;
}
