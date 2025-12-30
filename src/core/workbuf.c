// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wc/wc_workbuf.h"

#ifdef WC_WORKBUF_ENABLE_STATS
static wc_workbuf_stats_t g_wb_stats;
static inline void wc_workbuf_stats_note_reserve(size_t need, size_t oldcap, size_t newcap) {
    g_wb_stats.reserves++;
    if (newcap > oldcap) g_wb_stats.grow_events++;
    if (need > g_wb_stats.max_request) g_wb_stats.max_request = need;
    if (newcap > g_wb_stats.max_cap) g_wb_stats.max_cap = newcap;
}
static inline void wc_workbuf_stats_note_view(size_t abs_need) {
    if (abs_need > g_wb_stats.max_view_size) g_wb_stats.max_view_size = abs_need;
}
void wc_workbuf_stats_reset(void) { memset(&g_wb_stats, 0, sizeof(g_wb_stats)); }
wc_workbuf_stats_t wc_workbuf_stats_snapshot(void) { return g_wb_stats; }
#else
static inline void wc_workbuf_stats_note_reserve(size_t need, size_t oldcap, size_t newcap) { (void)need; (void)oldcap; (void)newcap; }
static inline void wc_workbuf_stats_note_view(size_t abs_need) { (void)abs_need; }
void wc_workbuf_stats_reset(void) {}
wc_workbuf_stats_t wc_workbuf_stats_snapshot(void) { wc_workbuf_stats_t z = {0,0,0,0,0}; return z; }
#endif

char* wc_workbuf_reserve(wc_workbuf_t* wb, size_t need, const char* where) {
    if (!wb) return NULL;
    size_t oldcap = wb->cap;
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
        wc_workbuf_stats_note_reserve(need + 1, oldcap, wb->cap);
    } else {
        wc_workbuf_stats_note_reserve(need + 1, oldcap, wb->cap);
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

char* wc_workbuf_view_alloc(wc_workbuf_view_t* view, size_t need, const char* where) {
    if (!view || !view->parent) return NULL;
    size_t abs_need = view->offset + view->cursor + need;
    wc_workbuf_stats_note_view(abs_need);
    char* base = wc_workbuf_reserve(view->parent, abs_need, where ? where : "wc_workbuf_view_alloc");
    char* ptr = base + view->offset + view->cursor;
    view->cursor += need;
    return ptr;
}

void wc_workbuf_free(wc_workbuf_t* wb) {
    if (!wb) return;
    if (wb->data) free(wb->data);
    wb->data = NULL;
    wb->cap = 0;
}
