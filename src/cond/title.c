// SPDX-License-Identifier: MIT
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include "wc/wc_title.h"

// Internal state for title projection
typedef struct {
    int enabled;
    char** patterns;
    int count;
} wc_title_state_t;

static wc_title_state_t s_title = {0, NULL, 0};

static void* xmalloc(size_t n, const char* where) {
    if (n == 0) n = 1;
    void* p = malloc(n);
    if (!p) {
        fprintf(stderr, "OOM in %s (%zu bytes)\n", where, (size_t)n);
        exit(EXIT_FAILURE);
    }
    return p;
}

static void* xrealloc(void* ptr, size_t n, const char* where) {
    if (n == 0) n = 1;
    void* p = realloc(ptr, n);
    if (!p) {
        fprintf(stderr, "OOM(realloc) in %s (%zu bytes)\n", where, (size_t)n);
        exit(EXIT_FAILURE);
    }
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

static char* str_tolower_dup_local(const char* s) {
    if (!s) return NULL;
    size_t n = strlen(s);
    char* r = (char*)xmalloc(n + 1, "str_tolower_dup_local");
    for (size_t i = 0; i < n; i++) r[i] = (char)tolower((unsigned char)s[i]);
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

static int ci_prefix_match_n_local(const char* name, size_t name_len, const char* pat) {
    if (!name || !pat) return 0;
    size_t plen = strlen(pat);
    if (plen == 0 || plen > name_len) return 0;
    for (size_t i = 0; i < plen; i++) {
        unsigned char a = (unsigned char)name[i];
        unsigned char b = (unsigned char)pat[i];
        if (tolower(a) != tolower(b)) return 0;
    }
    return 1;
}

void wc_title_set_enabled(int enabled) { s_title.enabled = enabled ? 1 : 0; }
int wc_title_is_enabled(void) { return s_title.enabled; }

void wc_title_free(void) {
    if (s_title.patterns) {
        for (int i = 0; i < s_title.count; ++i) {
            if (s_title.patterns[i]) free(s_title.patterns[i]);
        }
        free(s_title.patterns);
    }
    s_title.patterns = NULL;
    s_title.count = 0;
    s_title.enabled = 0;
}

int wc_title_parse_patterns(const char* arg) {
    if (!arg || !*arg) return 0;
    if (strlen(arg) > 4096) {
        fprintf(stderr, "Error: -g pattern string too long (max 4096)\n");
        return -1;
    }
    char* tmp = str_dup_local(arg);
    if (!tmp) return -1;
    int capacity = 16;
    char** pats = (char**)xmalloc(sizeof(char*) * capacity, "wc_title_parse_patterns");
    int count = 0;
    char* p = tmp;
    while (p) {
        char* token = p;
        char* bar = strchr(p, '|');
        if (bar) { *bar = '\0'; p = bar + 1; } else { p = NULL; }
        while (*token == ' ' || *token == '\t') token++;
        char* end = token + strlen(token);
        while (end > token && (end[-1] == ' ' || end[-1] == '\t')) { *--end = '\0'; }
        if (*token == '\0') continue;
        if ((int)strlen(token) > 128) {
            fprintf(stderr, "Error: -g pattern too long (max 128): %s\n", token);
            free(pats); free(tmp);
            return -1;
        }
        if (count >= 64) {
            fprintf(stderr, "Error: -g patterns exceed max count 64\n");
            free(pats); free(tmp);
            return -1;
        }
        char* lower = str_tolower_dup_local(token);
        if (!lower) { free(pats); free(tmp); return -1; }
        if (count >= capacity) {
            capacity *= 2;
            char** np = (char**)xrealloc(pats, sizeof(char*) * capacity, "wc_title_parse_patterns");
            pats = np;
        }
        pats[count++] = lower;
    }
    free(tmp);
    wc_title_free();
    s_title.patterns = pats;
    s_title.count = count;
    // Ensure the feature remains enabled when patterns are successfully parsed
    s_title.enabled = 1;
    return count;
}

char* wc_title_filter_response(const char* input) {
    if (!s_title.enabled || s_title.count <= 0 || !input) {
        return input ? str_dup_local(input) : str_dup_local("");
    }
    size_t in_len = strlen(input);
    char* out = (char*)xmalloc(in_len + 1, "wc_title_filter_response");
    size_t opos = 0;
    const char* p = input;
    int print_cont = 0;
    while (*p) {
        const char* line_start = p;
        const char* q = p;
        while (*q && *q != '\n') q++;
        size_t line_len = (size_t)(q - line_start);
        size_t det_len = line_len;
        if (det_len > 0 && line_start[det_len - 1] == '\r') det_len--;
        const char* hname = NULL; size_t hlen = 0; int leading_ws = 0;
        int is_header = is_header_line_and_name_local(line_start, det_len, &hname, &hlen, &leading_ws);
        int should_print = 0;
        if (is_header) {
            for (int i = 0; i < s_title.count; i++) {
                if (ci_prefix_match_n_local(hname, hlen, s_title.patterns[i])) { should_print = 1; break; }
            }
            print_cont = should_print;
        } else {
            if (print_cont && leading_ws) should_print = 1; else should_print = 0;
        }
        if (should_print) {
            memcpy(out + opos, line_start, line_len);
            opos += line_len;
            if (*q == '\n') { out[opos++] = '\n'; }
        }
        p = (*q == '\n') ? (q + 1) : q;
    }
    out[opos] = '\0';
    return out;
}
