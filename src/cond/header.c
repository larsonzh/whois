// SPDX-License-Identifier: MIT
#include <stddef.h>
#include <ctype.h>
#include "wc/wc_header.h"

int wc_header_parse(const char* line, size_t len, int allow_indented_header, wc_header_view_t* out) {
    if (out) {
        out->is_header = 0;
        out->is_cont = 0;
        out->leading_ws = 0;
        out->name = NULL;
        out->name_len = 0;
    }
    if (!line || len == 0) return 0;

    const char* s = line;
    const char* end = line + len;
    int leading_ws = 0;
    while (s < end && (*s == ' ' || *s == '\t')) { leading_ws = 1; s++; }

    if (leading_ws && !allow_indented_header) {
        if (out) {
            out->leading_ws = 1;
            out->is_cont = 1;
        }
        return 0;
    }

    const char* tok_start = s;
    while (s < end && *s != ' ' && *s != '\t' && *s != '\r' && *s != '\n') {
        if (*s == ':') break;
        s++;
    }

    if (s < end && *s == ':') {
        const char* name_start = tok_start;
        size_t nlen = (size_t)(s - name_start);
        if (nlen == 0) {
            if (out) out->leading_ws = leading_ws;
            return 0;
        }
        if (out) {
            out->is_header = 1;
            out->leading_ws = leading_ws;
            out->name = name_start;
            out->name_len = nlen;
        }
        return 1;
    }

    if (out) {
        out->leading_ws = leading_ws;
        out->is_cont = leading_ws ? 1 : 0;
    }
    return 0;
}
