// SPDX-License-Identifier: MIT
// lookup_exec.c - Phase B execution entry
#include <time.h>
#include "wc/wc_lookup.h"
#include "wc/wc_net.h"
#include "lookup_exec_internal.h"

struct wc_lookup_exec_state {
    const struct wc_query* q;
    const struct wc_lookup_opts* opts;
    struct wc_result* out;
};

static int wc_lookup_exec_prepare(struct wc_lookup_exec_state* st,
                                  const struct wc_query* q,
                                  const struct wc_lookup_opts* opts,
                                  struct wc_result* out) {
    if (!st || !q || !q->raw || !out) return -1;
    st->q = q;
    st->opts = opts;
    st->out = out;
    return 0;
}

static int wc_lookup_exec_postprocess(struct wc_lookup_exec_state* st, int rc) {
    (void)st;
    return rc;
}

static void wc_lookup_exec_now_ms(unsigned long long* out_ms)
{
#if defined(CLOCK_MONOTONIC)
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        *out_ms = (unsigned long long)ts.tv_sec * 1000ULL
                + (unsigned long long)(ts.tv_nsec / 1000000L);
        return;
    }
#endif
    *out_ms = (unsigned long long)time(NULL) * 1000ULL;
}

int wc_lookup_execute(const struct wc_query* q, const struct wc_lookup_opts* opts, struct wc_result* out) {
    struct wc_lookup_exec_state st;
    int prep_rc = wc_lookup_exec_prepare(&st, q, opts, out);
    if (prep_rc != 0) return prep_rc;

    // WP-04 timing/attempt instrumentation: sample at lifecycle start, write
    // deltas to the result metadata before returning.
    unsigned long long t0 = 0;
    unsigned int attempts0 = 0;
    wc_net_context_t* net_ctx = (opts && opts->net_ctx)
        ? opts->net_ctx : wc_net_context_get_active();
    wc_lookup_exec_now_ms(&t0);
    if (net_ctx)
        attempts0 = net_ctx->attempts;

    int rc = wc_lookup_exec_run(q, opts, out);

    if (out) {
        unsigned long long t1 = 0;
        wc_lookup_exec_now_ms(&t1);
        unsigned long long elapsed = (t1 >= t0) ? (t1 - t0) : 0;
        out->meta.duration_ms = (elapsed > 0xFFFFFFFFULL)
            ? 0xFFFFFFFFU : (unsigned int)elapsed;
        if (net_ctx) {
            unsigned int attempts_now = net_ctx->attempts;
            out->meta.attempts = (attempts_now >= attempts0)
                ? (attempts_now - attempts0) : 0;
        } else {
            out->meta.attempts = 0;
        }
    }
    return wc_lookup_exec_postprocess(&st, rc);
}
