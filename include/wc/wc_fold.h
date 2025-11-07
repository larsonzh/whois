// SPDX-License-Identifier: MIT
#ifndef WC_FOLD_H
#define WC_FOLD_H

#ifdef __cplusplus
extern "C" {
#endif

// 构建单行折叠输出：返回以'\n'结尾的堆内存字符串，需由调用方 free
// 参数：
//  - body: 经过条件筛选后的响应正文（可为 NULL）
//  - query: 原始查询串；若为空或疑似正则，将尝试从 body 的头标记中提取
//  - rir:   末尾附加的 RIR 名称（为空则使用 "unknown"）
//  - sep:   折叠各 token 的分隔符（NULL 则当作 " "）
//  - upper: 是否将 token/RIR 转为大写（非 0 则大写）
char* wc_fold_build_line(const char* body,
                         const char* query,
                         const char* rir,
                         const char* sep,
                         int upper);

#ifdef __cplusplus
}
#endif

#endif // WC_FOLD_H
