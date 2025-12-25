// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wc/wc_workbuf.h"

char* wc_workbuf_reserve(wc_workbuf_t* wb, size_t need, const char* where) {
    if (!wb) return NULL;
    if (need + 1 > wb->cap) {
        size_t newcap = wb->cap ? wb->cap : 256;
        while (need + 1 > newcap) newcap *= 2;
        char* np = (char*)realloc(wb->data, newcap);
        if (!np) {
            fprintf(stderr, "OOM in %s (%zu bytes)\n", where ? where : "wc_workbuf_reserve", (size_t)newcap);
            exit(EXIT_FAILURE);
        }
        wb->data = np;
        wb->cap = newcap;
    }
    return wb->data;
}

char* wc_workbuf_copy_cstr(wc_workbuf_t* wb, const char* src, const char* where) {
    if (!wb) return NULL;
    const char* safe = src ? src : "";
    size_t len = strlen(safe);
    char* base = wc_workbuf_reserve(wb, len, where ? where : "wc_workbuf_copy_cstr");
    if (base) memcpy(base, safe, len + 1);
    return base;
}

char* wc_workbuf_adopt_dup(wc_workbuf_t* wb, char* src_owned, const char* where) {
    if (!src_owned) return wc_workbuf_copy_cstr(wb, "", where);
    char* res = wc_workbuf_copy_cstr(wb, src_owned, where);
    free(src_owned);
    return res;
}

void wc_workbuf_free(wc_workbuf_t* wb) {
    if (!wb) return;
    if (wb->data) free(wb->data);
    wb->data = NULL;
    wb->cap = 0;
}
