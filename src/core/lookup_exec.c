// SPDX-License-Identifier: MIT
// lookup_exec.c - Phase B execution entry
#include "wc/wc_lookup.h"
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

int wc_lookup_execute(const struct wc_query* q, const struct wc_lookup_opts* opts, struct wc_result* out) {
    struct wc_lookup_exec_state st;
    int prep_rc = wc_lookup_exec_prepare(&st, q, opts, out);
    if (prep_rc != 0) return prep_rc;
    int rc = wc_lookup_exec_run(q, opts, out);
    return wc_lookup_exec_postprocess(&st, rc);
}
