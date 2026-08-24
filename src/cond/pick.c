// SPDX-License-Identifier: MIT
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wc/wc_header.h"
#include "wc/wc_pick.h"

#define WC_PICK_ARG_MAX 4096
#define WC_PICK_KEY_MAX 128
#define WC_PICK_COUNT_MAX 64
#define WC_PICK_VALUE_MAX 65536

static const char* const wc_pick_allowed_keys[] = {
    "netname", "country", "inetnum", "inet6num", "origin", "route", "descr"
};

typedef struct wc_pick_buf {
    char* data;
    size_t len;
    size_t cap;
} wc_pick_buf_t;

static int wc_pick_buf_reserve(wc_pick_buf_t* buf, size_t extra)
{
    size_t need = buf->len + extra + 1;
    if (need <= buf->cap)
        return 0;
    size_t cap = buf->cap ? buf->cap : 64;
    while (cap < need) {
        if (cap > ((size_t)-1) / 2)
            return -1;
        cap *= 2;
    }
    char* grown = (char*)realloc(buf->data, cap);
    if (!grown)
        return -1;
    buf->data = grown;
    buf->cap = cap;
    return 0;
}

static int wc_pick_buf_append_n(wc_pick_buf_t* buf, const char* text, size_t len)
{
    if (wc_pick_buf_reserve(buf, len) != 0)
        return -1;
    if (len)
        memcpy(buf->data + buf->len, text, len);
    buf->len += len;
    buf->data[buf->len] = '\0';
    return 0;
}

static int wc_pick_buf_append(wc_pick_buf_t* buf, const char* text)
{
    return wc_pick_buf_append_n(buf, text, text ? strlen(text) : 0);
}

static int wc_pick_key_equal(const char* left, size_t left_len,
        const char* right)
{
    size_t right_len = strlen(right);
    if (left_len != right_len)
        return 0;
    for (size_t i = 0; i < left_len; ++i) {
        if (tolower((unsigned char)left[i]) !=
                tolower((unsigned char)right[i]))
            return 0;
    }
    return 1;
}

static int wc_pick_allowed_index(const char* key, size_t len)
{
    for (size_t i = 0;
            i < sizeof(wc_pick_allowed_keys) / sizeof(wc_pick_allowed_keys[0]);
            ++i) {
        if (wc_pick_key_equal(key, len, wc_pick_allowed_keys[i]))
            return (int)i;
    }
    return -1;
}

int wc_pick_parse_keys(const char* arg, char** canonical_out)
{
    if (!canonical_out)
        return -1;
    *canonical_out = NULL;
    if (!arg || !*arg) {
        fprintf(stderr, "Error: --pick requires a non-empty key list\n");
        return -1;
    }
    size_t arg_len = strlen(arg);
    if (arg_len > WC_PICK_ARG_MAX) {
        fprintf(stderr, "Error: --pick key list too long (max 4096)\n");
        return -1;
    }

    char* copy = (char*)malloc(arg_len + 1);
    char* canonical = (char*)malloc(arg_len + 1);
    if (!copy || !canonical) {
        free(copy);
        free(canonical);
        fprintf(stderr, "Error: OOM parsing --pick\n");
        return -1;
    }
    memcpy(copy, arg, arg_len + 1);
    size_t out_len = 0;
    int token_count = 0;
    unsigned int seen = 0;
    char* token = copy;
    for (;;) {
        char* comma = strchr(token, ',');
        if (comma)
            *comma = '\0';
        ++token_count;
        if (token_count > WC_PICK_COUNT_MAX) {
            fprintf(stderr, "Error: --pick keys exceed max count 64\n");
            free(copy);
            free(canonical);
            return -1;
        }
        while (*token == ' ' || *token == '\t')
            ++token;
        char* end = token + strlen(token);
        while (end > token && (end[-1] == ' ' || end[-1] == '\t'))
            --end;
        size_t key_len = (size_t)(end - token);
        if (key_len == 0) {
            fprintf(stderr, "Error: --pick contains an empty key\n");
            free(copy);
            free(canonical);
            return -1;
        }
        if (key_len > WC_PICK_KEY_MAX) {
            fprintf(stderr, "Error: --pick key too long (max 128)\n");
            free(copy);
            free(canonical);
            return -1;
        }
        int key_index = wc_pick_allowed_index(token, key_len);
        if (key_index < 0) {
            fprintf(stderr, "Error: Unsupported --pick key '%.*s'\n",
                (int)key_len, token);
            free(copy);
            free(canonical);
            return -1;
        }
        unsigned int bit = 1u << (unsigned int)key_index;
        if (!(seen & bit)) {
            if (out_len)
                canonical[out_len++] = ',';
            const char* allowed = wc_pick_allowed_keys[key_index];
            size_t allowed_len = strlen(allowed);
            memcpy(canonical + out_len, allowed, allowed_len);
            out_len += allowed_len;
            seen |= bit;
        }
        if (!comma)
            break;
        token = comma + 1;
    }
    canonical[out_len] = '\0';
    free(copy);
    *canonical_out = canonical;
    return 0;
}

static int wc_pick_append_normalized(wc_pick_buf_t* out,
        const char* text, size_t len)
{
    int emitted = 0;
    int pending_space = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)text[i];
        if (c <= 32 || c == 127) {
            if (emitted)
                pending_space = 1;
            continue;
        }
        if (pending_space) {
            if (wc_pick_buf_append_n(out, " ", 1) != 0)
                return -1;
            pending_space = 0;
        }
        if (wc_pick_buf_append_n(out, (const char*)&text[i], 1) != 0)
            return -1;
        emitted = 1;
    }
    return 0;
}

static int wc_pick_commit_occurrence(wc_pick_buf_t* values,
        int* seen, int key_index, enum wc_pick_mode mode,
    const wc_pick_buf_t* occurrence)
{
    if (key_index < 0 || (mode == WC_PICK_MODE_FIRST && seen[key_index]))
        return 0;
    wc_pick_buf_t addition = {0};
    if (mode == WC_PICK_MODE_JOIN && seen[key_index] &&
            wc_pick_buf_append_n(&addition, "|", 1) != 0)
        return -1;
    if (wc_pick_buf_append_n(&addition,
            occurrence->data ? occurrence->data : "", occurrence->len) != 0) {
        free(addition.data);
        return -1;
    }
    size_t value_budget = values[key_index].len < WC_PICK_VALUE_MAX
        ? WC_PICK_VALUE_MAX - values[key_index].len : 0;
    size_t take = addition.len;
    int truncated = take > value_budget;
    if (truncated)
        take = value_budget;
    if (wc_pick_buf_append_n(&values[key_index], addition.data, take) != 0) {
        free(addition.data);
        return -1;
    }
    if (truncated && values[key_index].len >= 3) {
        memcpy(values[key_index].data + values[key_index].len - 3, "...", 3);
    }
    free(addition.data);
    seen[key_index] = 1;
    return 0;
}

char* wc_pick_build_line(const char* filtered_view,
        const char* canonical_keys, enum wc_pick_mode mode)
{
    if (!canonical_keys || !*canonical_keys)
        return NULL;
    int requested[7];
    size_t requested_count = 0;
    const char* key = canonical_keys;
    while (*key && requested_count < 7) {
        const char* comma = strchr(key, ',');
        size_t len = comma ? (size_t)(comma - key) : strlen(key);
        int index = wc_pick_allowed_index(key, len);
        if (index >= 0)
            requested[requested_count++] = index;
        if (!comma)
            break;
        key = comma + 1;
    }

    wc_pick_buf_t values[7] = {{0}};
    int seen[7] = {0};
    wc_pick_buf_t occurrence = {0};
    int current = -1;
    const char* cursor = filtered_view ? filtered_view : "";
    while (*cursor) {
        const char* line_end = strchr(cursor, '\n');
        size_t line_len = line_end ? (size_t)(line_end - cursor) : strlen(cursor);
        if (line_len && cursor[line_len - 1] == '\r')
            --line_len;
        wc_header_view_t header;
        memset(&header, 0, sizeof(header));
        if (wc_header_parse(cursor, line_len, 1, &header)) {
                if (wc_pick_commit_occurrence(values, seen, current, mode,
                    &occurrence) != 0)
                goto oom;
            occurrence.len = 0;
            if (occurrence.data)
                occurrence.data[0] = '\0';
            current = -1;
            int index = wc_pick_allowed_index(header.name, header.name_len);
            if (index >= 0 && !(mode == WC_PICK_MODE_FIRST && seen[index])) {
                current = index;
                const char* value = header.name + header.name_len + 1;
                size_t value_len = (size_t)((cursor + line_len) - value);
                if (wc_pick_append_normalized(&occurrence, value, value_len) != 0)
                    goto oom;
            }
        } else if (current >= 0 && header.leading_ws) {
            wc_pick_buf_t continuation = {0};
            if (wc_pick_append_normalized(&continuation, cursor, line_len) != 0) {
                free(continuation.data);
                goto oom;
            }
            if (continuation.len) {
                if (wc_pick_buf_append(&occurrence, "; ") != 0 ||
                        wc_pick_buf_append_n(&occurrence,
                            continuation.data, continuation.len) != 0) {
                    free(continuation.data);
                    goto oom;
                }
            }
            free(continuation.data);
        }
        if (!line_end)
            break;
        cursor = line_end + 1;
    }
        if (wc_pick_commit_occurrence(values, seen, current, mode,
            &occurrence) != 0)
        goto oom;

    wc_pick_buf_t output = {0};
    for (size_t i = 0; i < requested_count; ++i) {
        int index = requested[i];
        if (i && wc_pick_buf_append_n(&output, "\t", 1) != 0)
            goto output_oom;
        if (wc_pick_buf_append(&output, wc_pick_allowed_keys[index]) != 0 ||
                wc_pick_buf_append_n(&output, "=", 1) != 0 ||
                wc_pick_buf_append_n(&output,
                    values[index].data ? values[index].data : "",
                    values[index].len) != 0)
            goto output_oom;
    }
    if (wc_pick_buf_append_n(&output, "\n", 1) != 0)
        goto output_oom;
    for (size_t i = 0; i < 7; ++i)
        free(values[i].data);
    free(occurrence.data);
    return output.data;

output_oom:
    free(output.data);
oom:
    for (size_t i = 0; i < 7; ++i)
        free(values[i].data);
    free(occurrence.data);
    fprintf(stderr, "Error: OOM building --pick output\n");
    return NULL;
}