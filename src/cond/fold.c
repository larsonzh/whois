// SPDX-License-Identifier: MIT
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "wc/wc_fold.h"

// Minimal fold-line implementation, decoupled from runtime config.
// Formatting is controlled by sep/upper arguments; local helpers are provided.

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
                                     const char* sep, int upper) {
    if (!sep) sep = " ";
    size_t seplen = strlen(sep);
    if (*len > 0) {
        while (*len + seplen >= *cap) { *cap = (*cap ? *cap*2 : 128); *out = (char*)realloc(*out, *cap); }
        memcpy((*out)+(*len), sep, seplen);
        *len += seplen;
    }
    int in_space = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '\r' || c == '\n') break;
        if (c == ' ' || c == '\t') { in_space = 1; continue; }
        if (in_space) {
            while (*len + 1 >= *cap) { *cap = (*cap ? *cap*2 : 128); *out = (char*)realloc(*out, *cap); }
            (*out)[(*len)++] = ' ';
            in_space = 0;
        }
        char ch = upper ? (char)toupper(c) : (char)c;
        while (*len + 1 >= *cap) { *cap = (*cap ? *cap*2 : 128); *out = (char*)realloc(*out, *cap); }
        (*out)[(*len)++] = ch;
    }
}

static int g_fold_unique = 0;

void wc_fold_set_unique(int on) { g_fold_unique = on ? 1 : 0; }

char* wc_fold_build_line(const char* body,
                         const char* query,
                         const char* rir,
                         const char* sep,
                         int upper) {
    size_t cap = 256, len = 0;
    char* out = (char*)malloc(cap);
    if (!out) {
        char* z = (char*)malloc(1);
        if (z) z[0] = '\0';
        return z;
    }

    // Select query: prefer the function parameter; otherwise try extracting from body.
    char qbuf[256];
    const char* qsrc = query;
    if (!qsrc || !*qsrc || is_likely_regex_local(qsrc)) {
        const char* from_body = extract_query_from_body_local(body, qbuf, sizeof(qbuf));
        if (from_body && *from_body) qsrc = from_body;
    }
    if (!qsrc) qsrc = "";
    size_t qlen = strlen(qsrc);
    while (len + qlen + 1 >= cap) { cap *= 2; out = (char*)realloc(out, cap); }
    memcpy(out + len, qsrc, qlen); len += qlen;

    // Scan body lines and extract values from header/continuation lines.
    // Collect tokens into a temporary array if unique mode is enabled.
    typedef struct { char* s; } Token;
    Token* toks = NULL; size_t tok_count = 0; size_t tok_cap = 0;
    if (body) {
        const char* p = body;
        while (*p) {
            const char* line_start = p;
            const char* q = p;
            while (*q && *q != '\n') q++;
            size_t line_len = (size_t)(q - line_start);
            size_t det_len = line_len; if (det_len>0 && line_start[det_len-1]=='\r') det_len--;

            const char* hname = NULL; size_t hlen = 0; int leading_ws = 0;
            int is_header = is_header_line_and_name_local(line_start, det_len, &hname, &hlen, &leading_ws);
            if (is_header) {
                const char* colon = memchr(line_start, ':', det_len);
                if (colon) {
                    const char* val = colon + 1;
                    while (val < line_start + det_len && (*val==' ' || *val=='\t')) val++;
                    if (g_fold_unique) {
                        size_t vlen = (size_t)((line_start + det_len) - val);
                        char* tmp = (char*)malloc(vlen + 1);
                        if (tmp) { memcpy(tmp, val, vlen); tmp[vlen] = '\0'; }
                        if (tok_count + 1 > tok_cap) { tok_cap = tok_cap ? tok_cap*2 : 16; toks = (Token*)realloc(toks, tok_cap * sizeof(Token)); }
                        toks[tok_count++].s = tmp;
                    } else {
                        append_token_with_format(&out, &cap, &len, val,
                                                 (size_t)((line_start + det_len) - val),
                                                 sep, upper);
                    }
                }
            } else if (leading_ws) {
                const char* s2 = line_start;
                while (s2 < line_start + det_len && (*s2==' ' || *s2=='\t')) s2++;
                if (s2 < line_start + det_len) {
                    if (g_fold_unique) {
                        size_t vlen = (size_t)((line_start + det_len) - s2);
                        char* tmp = (char*)malloc(vlen + 1);
                        if (tmp) { memcpy(tmp, s2, vlen); tmp[vlen] = '\0'; }
                        if (tok_count + 1 > tok_cap) { tok_cap = tok_cap ? tok_cap*2 : 16; toks = (Token*)realloc(toks, tok_cap * sizeof(Token)); }
                        toks[tok_count++].s = tmp;
                    } else {
                        append_token_with_format(&out, &cap, &len, s2,
                                                 (size_t)((line_start + det_len) - s2),
                                                 sep, upper);
                    }
                }
            }
            p = (*q == '\n') ? (q + 1) : q;
        }
    }

    // If unique mode: de-duplicate tokens preserving first occurrence order.
    if (g_fold_unique && tok_count > 0) {
        for (size_t i = 0; i < tok_count; i++) {
            if (!toks[i].s) continue;
            int seen = 0;
            for (size_t j = 0; j < i; j++) {
                if (toks[j].s && strcmp(toks[j].s, toks[i].s) == 0) { seen = 1; break; }
            }
            if (!seen) {
                append_token_with_format(&out, &cap, &len, toks[i].s, strlen(toks[i].s), sep, upper);
            }
        }
        for (size_t i = 0; i < tok_count; i++) { if (toks[i].s) free(toks[i].s); }
        free(toks);
    }

    // Append RIR token at the end.
    const char* rirv = (rir && *rir) ? rir : "unknown";
    append_token_with_format(&out, &cap, &len, rirv, strlen(rirv), sep, upper);

    if (len + 2 >= cap) { cap += 2; out = (char*)realloc(out, cap); }
    out[len++] = '\n'; out[len] = '\0';
    return out;
}
