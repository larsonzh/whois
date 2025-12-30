// SPDX-License-Identifier: MIT
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "wc/wc_fold.h"
#include "wc/wc_workbuf.h"
#include "wc/wc_header.h"

// Minimal fold-line implementation, decoupled from runtime config.
// Formatting is controlled by sep/upper arguments; local helpers are provided.

// Heuristic to detect if a string looks like a regex (kept consistent with main).
static int is_likely_regex_local(const char* s) {
    if (!s || !*s) return 0;
    int has_meta = 0, has_sep = 0;
    for (const char* p = s; *p; ++p) {
        char c = *p;
        if (c=='^' || c=='$' || c=='[' || c==']' || c=='(' || c==')' || c=='|' || c=='?' || c=='+' || c=='*' || c=='{' || c=='}') has_meta = 1;
        if (c==' ' || c=='\t' || c=='|') has_sep = 1;
        if (has_meta && has_sep) return 1;
    }
    return 0;
}

// Try to extract query from header marker lines inside body: "=== Query: <q> ===".
static const char* extract_query_from_body_local(const char* body, char* buf, size_t bufsz) {
    if (!body || !buf || bufsz==0) return NULL;
    const char* p = body;
    const char* marker = "=== Query:";
    size_t mlen = strlen(marker);
    while (*p) {
        const char* line = p;
        const char* q = p;
        while (*q && *q!='\n') q++;
        size_t len = (size_t)(q - line);
        const char* end = line + len;
        if (len >= mlen && memcmp(line, marker, mlen)==0) {
            const char* s = line + mlen;
            while (s<end && (*s==' ' || *s=='\t')) s++;
            while (end>s && (end[-1]==' ' || end[-1]=='\t')) end--;
            while (end>s && end[-1]=='=') end--;
            while (end>s && (end[-1]==' ' || end[-1]=='\t')) end--;
            size_t qlen = (size_t)(end - s);
            if (qlen > 0) {
                if (qlen >= bufsz) qlen = bufsz - 1;
                memcpy(buf, s, qlen); buf[qlen] = '\0';
                return buf;
            }
        }
        p = (*q=='\n') ? (q+1) : q;
    }
    return NULL;
}

// Append a token: collapse internal whitespace to a single space; optional upper-case;
// add separator between tokens.
static void append_token_with_format(char** out, size_t* cap, size_t* len,
                                     const char* s, size_t n,
                                     const char* sep, int upper,
                                     wc_workbuf_t* wb) {
    if (!sep) sep = " ";
    size_t seplen = strlen(sep);
    if (*len > 0) {
        wc_workbuf_reserve(wb, *len + seplen, "wc_fold_append_token");
        *out = wb->data; *cap = wb->cap;
        memcpy((*out)+(*len), sep, seplen);
        *len += seplen;
    }
    int in_space = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '\r' || c == '\n') break;
        if (c == ' ' || c == '\t') { in_space = 1; continue; }
        if (in_space) {
            wc_workbuf_reserve(wb, *len + 1, "wc_fold_append_token");
            *out = wb->data; *cap = wb->cap;
            (*out)[(*len)++] = ' ';
            in_space = 0;
        }
        char ch = upper ? (char)toupper(c) : (char)c;
        wc_workbuf_reserve(wb, *len + 1, "wc_fold_append_token");
        *out = wb->data; *cap = wb->cap;
        (*out)[(*len)++] = ch;
    }
}

static int g_fold_unique = 0;

void wc_fold_set_unique(int on) { g_fold_unique = on ? 1 : 0; }

char* wc_fold_build_line_wb(const char* body,
                            const char* query,
                            const char* rir,
                            const char* sep,
                            int upper,
                            wc_workbuf_t* wb) {
    if (!wb) return NULL;
    wc_workbuf_reserve(wb, 256, "wc_fold_build_line_wb");
    size_t cap = wb->cap;
    size_t len = 0;
    char* out = wb->data;

    typedef struct {
        const char* s;
        size_t len;
    } TokenView;
    wc_workbuf_t scratch; wc_workbuf_init(&scratch);
    TokenView* toks = NULL; size_t tok_count = 0; size_t tok_cap = 0;

    // Select query: prefer the function parameter; otherwise try extracting from body.
    char qbuf[256];
    const char* qsrc = query;
    if (!qsrc || !*qsrc || is_likely_regex_local(qsrc)) {
        const char* from_body = extract_query_from_body_local(body, qbuf, sizeof(qbuf));
        if (from_body && *from_body) qsrc = from_body;
    }
    if (!qsrc) qsrc = "";
    size_t qlen = strlen(qsrc);
    wc_workbuf_reserve(wb, len + qlen, "wc_fold_build_line_wb");
    out = wb->data; cap = wb->cap;
    memcpy(out + len, qsrc, qlen); len += qlen;

    // Scan body lines and extract values from header/continuation lines.
    // Collect tokens into a temporary array if unique mode is enabled.
    if (body) {
        const char* p = body;
        while (*p) {
            const char* line_start = p;
            const char* q = p;
            while (*q && *q != '\n') q++;
            size_t line_len = (size_t)(q - line_start);
            size_t det_len = line_len; if (det_len>0 && line_start[det_len-1]=='\r') det_len--;

            wc_header_view_t hv; memset(&hv, 0, sizeof(hv));
            int is_header = wc_header_parse(line_start, det_len, 1, &hv);
            if (is_header) {
                const char* colon = memchr(line_start, ':', det_len);
                if (colon) {
                    const char* val = colon + 1;
                    while (val < line_start + det_len && (*val==' ' || *val=='\t')) val++;
                    if (g_fold_unique) {
                        size_t vlen = (size_t)((line_start + det_len) - val);
                        if (tok_count + 1 > tok_cap) {
                            size_t need = (tok_cap ? tok_cap*2 : 16) * sizeof(TokenView);
                            TokenView* base = (TokenView*)wc_workbuf_reserve(&scratch, need, "wc_fold_tokens");
                            tok_cap = tok_cap ? tok_cap*2 : 16;
                            if (toks) memcpy(base, toks, tok_count * sizeof(TokenView));
                            toks = base;
                        }
                        toks[tok_count].s = val;
                        toks[tok_count].len = vlen;
                        tok_count++;
                    } else {
                        append_token_with_format(&out, &cap, &len, val,
                                                 (size_t)((line_start + det_len) - val),
                                                 sep, upper, wb);
                    }
                }
            } else if (hv.leading_ws) {
                const char* s2 = line_start;
                while (s2 < line_start + det_len && (*s2==' ' || *s2=='\t')) s2++;
                if (s2 < line_start + det_len) {
                    if (g_fold_unique) {
                        size_t vlen = (size_t)((line_start + det_len) - s2);
                        if (tok_count + 1 > tok_cap) {
                            size_t need = (tok_cap ? tok_cap*2 : 16) * sizeof(TokenView);
                            TokenView* base = (TokenView*)wc_workbuf_reserve(&scratch, need, "wc_fold_tokens");
                            tok_cap = tok_cap ? tok_cap*2 : 16;
                            if (toks) memcpy(base, toks, tok_count * sizeof(TokenView));
                            toks = base;
                        }
                        toks[tok_count].s = s2;
                        toks[tok_count].len = vlen;
                        tok_count++;
                    } else {
                        append_token_with_format(&out, &cap, &len, s2,
                                                 (size_t)((line_start + det_len) - s2),
                                                 sep, upper, wb);
                    }
                }
            }
            p = (*q == '\n') ? (q + 1) : q;
        }
    }

    // If unique mode: de-duplicate tokens preserving first occurrence order.
    if (g_fold_unique && tok_count > 0) {
        for (size_t i = 0; i < tok_count; i++) {
            int seen = 0;
            for (size_t j = 0; j < i; j++) {
                if (toks[j].len == toks[i].len && memcmp(toks[j].s, toks[i].s, toks[i].len) == 0) { seen = 1; break; }
            }
            if (!seen) {
                append_token_with_format(&out, &cap, &len, toks[i].s, toks[i].len, sep, upper, wb);
            }
        }
    }

    // Append RIR token at the end.
    const char* rirv = (rir && *rir) ? rir : "unknown";
    append_token_with_format(&out, &cap, &len, rirv, strlen(rirv), sep, upper, wb);

    wc_workbuf_reserve(wb, len + 1, "wc_fold_build_line_wb_tail");
    out = wb->data; cap = wb->cap;
    out[len++] = '\n'; out[len] = '\0';
    wc_workbuf_free(&scratch);
    return out;
}

char* wc_fold_build_line(const char* body,
                         const char* query,
                         const char* rir,
                         const char* sep,
                         int upper) {
    wc_workbuf_t wb; wc_workbuf_init(&wb);
    char* view = wc_fold_build_line_wb(body, query, rir, sep, upper, &wb);
    size_t len = view ? strlen(view) : 0;
    char* out = (char*)malloc(len + 1);
    if (out) {
        if (view) memcpy(out, view, len + 1); else out[0] = '\0';
    }
    wc_workbuf_free(&wb);
    return out;
}
