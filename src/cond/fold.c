// SPDX-License-Identifier: MIT
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "wc/wc_fold.h"

// 本模块为“折叠输出”最小可用实现，避免对主模块 g_config 的直接依赖
// 通过调用方传入 sep/upper 控制格式；内部局部实现必要的小工具函数

// 识别行首 header 名称和是否为续行：
//  - 返回 1 表示 header 行，name_ptr/name_len_ptr 指向不含 ':' 的字段名
//  - leading_ws_ptr 返回该行是否以空白开头（用于续行识别）
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

// 判断是否“像正则”的启发式（与主文件保持一致）
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

// 从正文里尝试提取头标记行里的 Query："=== Query: <q> ==="
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

// 附加 token：合并内部空白为单空格；可选大写；在前一个 token 后添加分隔符
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

    // 选择 query：优先参数，其次尝试从 body 提取
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

    // 扫描正文行，抽取 header/续行的值
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
                    append_token_with_format(&out, &cap, &len, val,
                                             (size_t)((line_start + det_len) - val),
                                             sep, upper);
                }
            } else if (leading_ws) {
                const char* s2 = line_start;
                while (s2 < line_start + det_len && (*s2==' ' || *s2=='\t')) s2++;
                if (s2 < line_start + det_len) {
                    append_token_with_format(&out, &cap, &len, s2,
                                             (size_t)((line_start + det_len) - s2),
                                             sep, upper);
                }
            }
            p = (*q == '\n') ? (q + 1) : q;
        }
    }

    // 追加 RIR
    const char* rirv = (rir && *rir) ? rir : "unknown";
    append_token_with_format(&out, &cap, &len, rirv, strlen(rirv), sep, upper);

    if (len + 2 >= cap) { cap += 2; out = (char*)realloc(out, cap); }
    out[len++] = '\n'; out[len] = '\0';
    return out;
}
