#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "wc/wc_pipeline.h"
#include "wc/wc_client_flow.h"
#include "wc/wc_dns.h"
#include "wc/wc_fold.h"
#include "wc/wc_grep.h"
#include "wc/wc_output.h"
#include "wc/wc_title.h"
#include "wc/wc_util.h"
#include "wc/wc_workbuf.h"

// Temporary thin wrapper around existing client_flow dispatch. This allows
// main() to delegate to a single pipeline entry while we migrate batch
// runner/pipeline logic without changing behavior.
int wc_pipeline_run(const wc_opts_t* opts, int argc, char* const* argv, const Config* config)
{
    return wc_client_run_with_mode(opts, argc, argv, config);
}

// Normalize CR-only/CRLF sequences to LF in-place.
static char* normalize_line_endings_inplace(char* buf)
{
    if (!buf)
        return NULL;
    if (!strchr(buf, '\r'))
        return buf;
    char* dst = buf;
    for (char* src = buf; *src; ++src) {
        if (*src == '\r') {
            *dst++ = '\n';
            if (src[1] == '\n')
                ++src; // collapse CRLF into single LF
        } else {
            *dst++ = *src;
        }
    }
    *dst = '\0';
    return buf;
}

// Drop control chars/ANSI escapes and canonicalize newlines for stdout safety.
static char* sanitize_response_for_output_wb(const Config* config,
        const char* input,
        wc_workbuf_t* wb)
{
    int debug = config && config->debug;
    if (!input || !wb)
        return NULL;
    size_t len = strlen(input);
    char* output = wc_workbuf_reserve(wb, len, __func__);
    size_t out_pos = 0;
    int in_escape = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = input[i];
        if (c == 0)
            continue;
        if (c == '\r') {
            output[out_pos++] = '\n';
            if (i + 1 < len && input[i + 1] == '\n')
                ++i; // collapse CRLF into a single LF
            continue;
        }
        if (c == '\n') {
            output[out_pos++] = '\n';
            continue;
        }
        if (c < 32 && c != '\t') {
            output[out_pos++] = ' ';
            continue;
        }
        if (c == '\033') {
            in_escape = 1;
            continue;
        }
        if (in_escape) {
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
                in_escape = 0;
            continue;
        }
        output[out_pos++] = c;
    }
    output[out_pos] = '\0';
    if (out_pos != len && debug) {
        wc_output_log_message("DEBUG",
            "Sanitized response: removed %zu problematic characters",
            len - out_pos);
    }
    return output;
}

char* wc_apply_response_filters(const Config* config,
        const char* query,
        const char* raw_response,
        int in_batch,
        wc_workbuf_t* wb)
{
    (void)query;
    int debug = config && config->debug;
    if (!raw_response || !wb)
        return NULL;
    char* result = wc_workbuf_copy_cstr(wb, raw_response, __func__);
    result = normalize_line_endings_inplace(result);

    if (wc_title_is_enabled()) {
        if (debug) {
            fprintf(stderr,
                in_batch ? "[TRACE][batch] stage=title_filter in\n"
                        : "[TRACE] stage=title_filter in\n");
        }
        result = wc_title_filter_response_wb(result, wb);
        if (debug) {
            fprintf(stderr,
                in_batch ? "[TRACE][batch] stage=title_filter out ptr=%p\n"
                        : "[TRACE] stage=title_filter out ptr=%p\n",
                (void*)result);
        }
    }

    if (wc_grep_is_enabled()) {
        if (debug) {
            fprintf(stderr,
                in_batch ? "[TRACE][batch] stage=grep_filter in\n"
                        : "[TRACE] stage=grep_filter in\n");
        }
        result = wc_grep_filter_wb(result, wb);
        if (debug) {
            fprintf(stderr,
                in_batch ? "[TRACE][batch] stage=grep_filter out ptr=%p\n"
                        : "[TRACE] stage=grep_filter out ptr=%p\n",
                (void*)result);
        }
    }

    if (debug) {
        fprintf(stderr,
            in_batch ? "[TRACE][batch] stage=sanitize in ptr=%p\n"
                    : "[TRACE] stage=sanitize in ptr=%p\n",
            (void*)result);
    }
    result = sanitize_response_for_output_wb(config, result, wb);
    if (debug && result) {
        fprintf(stderr,
            in_batch ? "[TRACE][batch] stage=sanitize out ptr=%p len=%zu\n"
                    : "[TRACE] stage=sanitize out ptr=%p len=%zu\n",
            (void*)result, strlen(result));
    }
    return result;
}

// Map authoritative IP literals back to canonical RIR hosts for tail rendering.
static const char* wc_pipeline_resolve_authoritative_display(const Config* cfg,
        const struct wc_result* res,
        char** owned_out)
{
    if (owned_out)
        *owned_out = NULL;
    if (!res)
        return NULL;
    const char* authoritative_display =
        (res->meta.authoritative_host[0]
            ? res->meta.authoritative_host
            : NULL);
    if (authoritative_display && wc_dns_is_ip_literal(authoritative_display)) {
        char* mapped = wc_dns_rir_fallback_from_ip(cfg, authoritative_display);
        if (mapped) {
            if (owned_out)
                *owned_out = mapped;
            return mapped;
        }
    }
    return authoritative_display;
}

static void wc_pipeline_render_tail(const wc_client_render_opts_t* render_opts,
        const struct wc_result* res,
        const char* authoritative_display)
{
    if (!render_opts || render_opts->plain_mode)
        return;
    if (authoritative_display && *authoritative_display) {
        const char* auth_ip =
            (res && res->meta.authoritative_ip[0]
                ? res->meta.authoritative_ip
                : "unknown");
        wc_output_tail_authoritative_ip(authoritative_display, auth_ip);
    } else {
        wc_output_tail_unknown_unknown();
    }
}

// Centralized render pipeline used by both batch and single-query paths.
void wc_pipeline_render(const Config* cfg,
        const wc_client_render_opts_t* render_opts,
        const char* query,
        const char* via_host_default,
        struct wc_result* res,
        int in_batch)
{
    if (!res)
        return;
    const int debug = render_opts ? render_opts->debug : 0;
    char* raw_body = res->body;
    size_t body_len = res->body_len;
    res->body = NULL;
    res->body_len = 0;
    wc_workbuf_t filter_wb; wc_workbuf_init(&filter_wb);
    if (debug) {
        fprintf(stderr,
            in_batch
                ? "[TRACE][batch] after header; body_ptr=%p len=%zu (stage=initial)\n"
                : "[TRACE] after header; body_ptr=%p len=%zu (stage=initial)\n",
            (void*)raw_body, body_len);
    }
    const int fold_output = render_opts ? render_opts->fold_output : 0;
    const int plain_mode = render_opts ? render_opts->plain_mode : 0;
    if (!fold_output && !plain_mode) {
        const char* via_host = res->meta.via_host[0]
            ? res->meta.via_host
            : (via_host_default ? via_host_default : "whois.iana.org");
        const char* via_ip = res->meta.via_ip[0]
            ? res->meta.via_ip
            : NULL;
        if (via_ip)
            wc_output_header_via_ip(query, via_host, via_ip);
        else
            wc_output_header_via_unknown(query, via_host);
        if (in_batch)
            fflush(stdout);
    }
    char* filtered = wc_apply_response_filters(cfg, query, raw_body,
        in_batch, &filter_wb);
    free(raw_body);

    char* authoritative_display_owned = NULL;
    const char* authoritative_display = wc_pipeline_resolve_authoritative_display(
        cfg, res, &authoritative_display_owned);

    if (fold_output) {
        const char* rirv =
            (authoritative_display && *authoritative_display)
                ? authoritative_display
                : "unknown";
        char* folded = wc_fold_build_line_wb(
            filtered, query, rirv,
            render_opts ? render_opts->fold_sep : " ",
            render_opts ? render_opts->fold_upper : 0,
            &filter_wb);
        printf("%s", folded);
    } else {
        printf("%s", filtered);
        if (filtered && *filtered) {
            size_t flen = strlen(filtered);
            if (flen > 0 && filtered[flen - 1] != '\n') {
                printf("\n");
            }
        }
        wc_pipeline_render_tail(render_opts, res, authoritative_display);
    }
    if (authoritative_display_owned)
        free(authoritative_display_owned);
    wc_workbuf_free(&filter_wb);
}
