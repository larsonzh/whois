// meta.c - Help/Version/Usage metadata utilities for whois client
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "wc/wc_meta.h"

#ifndef WHOIS_VERSION
#define WHOIS_VERSION "3.2.4"
#endif

static void print_common_header(const char* program_name) {
    const char* lang = getenv("WHOIS_LANG");
    if (!lang) lang = "en";
    if (strcmp(lang, "zh") == 0) {
        printf("用法: %s [OPTIONS] <IP或域名>\n\n", program_name ? program_name : "whois");
        printf("轻量级静态 whois 客户端：支持重定向跟随、标题投影、正则筛选与折叠输出。\n\n");
    } else {
        printf("Usage: %s [OPTIONS] <IP or domain>\n\n", program_name ? program_name : "whois");
        printf("Lightweight static whois client: redirects follow, title projection, regex filtering, fold output.\n\n");
    }
}

void wc_meta_print_usage(
    const char* program_name,
    int default_port,
    size_t default_buffer,
    int default_retries,
    int default_timeout_sec,
    int default_retry_interval_ms,
    int default_retry_jitter_ms,
    int default_max_redirects,
    int default_dns_cache_size,
    int default_connection_cache_size,
    int default_cache_timeout,
    int default_debug)
{
    (void)default_debug; // reserved for future conditional help verbosity
    print_common_header(program_name);

    const char* lang = getenv("WHOIS_LANG"); if (!lang) lang = "en";
    if (strcmp(lang, "zh") == 0) {
        printf("核心选项:\n");
        printf("  -H, --help                显示帮助并退出\n");
        printf("  -v, --version             显示版本并退出\n");
        printf("  -l, --list                列出内置 RIR 服务器\n");
        printf("      --about               显示详细功能/模块说明\n");
        printf("      --examples            显示更多示例\n");
        printf("  -B, --batch               批量模式：从 stdin 读取（每行一个查询）\n");
    } else {
        printf("Core options:\n");
        printf("  -H, --help                Show this help message and exit\n");
        printf("  -v, --version             Show version and exit\n");
        printf("  -l, --list                List known RIR servers\n");
        printf("      --about               Show detailed information about features and modules\n");
        printf("      --examples            Show extended examples\n");
        printf("  -B, --batch               Batch mode: read queries from stdin (one per line)\n");
    }
    printf("  -H, --help                Show this help message and exit\n");
    printf("  -v, --version             Show version and exit\n");
    printf("  -l, --list                List known RIR servers\n");
    printf("      --about               Show detailed information about features and modules\n");
    printf("      --examples            Show extended examples\n");
    printf("  -B, --batch               Batch mode: read queries from stdin (one per line)\n");
    printf("  -h, --host HOST           Start from specific whois server (name|domain|ip)\n");
    printf("  -p, --port PORT           Whois server port (default: %d)\n", default_port);
    printf("  -Q, --no-redirect         Do not follow referrals (default: follow up to %d)\n", default_max_redirects);
    printf("  -R, --max-hops N          Max referral hops (default: %d)\n", default_max_redirects);
    printf("  -P, --plain               Suppress header/tail lines (plain body only)\n");
    printf("  -D, --debug               Enable debug prints\n\n");

    if (strcmp(lang, "zh") == 0) {
        printf("超时与重试:\n");
        printf("      --timeout SEC         超时秒数 (默认: %d)\n", default_timeout_sec);
        printf("      --retries N           重试次数 (默认: %d)\n", default_retries);
        printf("      --retry-interval-ms M 基础重试间隔毫秒 (默认: %d)\n", default_retry_interval_ms);
        printf("      --retry-jitter-ms J   额外随机抖动毫秒 (默认: %d)\n\n", default_retry_jitter_ms);
    } else {
        printf("Timeouts & retries:\n");
        printf("      --timeout SEC         Socket timeout seconds (default: %d)\n", default_timeout_sec);
        printf("      --retries N           Retry count on transient errors (default: %d)\n", default_retries);
        printf("      --retry-interval-ms M Base interval between retries in ms (default: %d)\n", default_retry_interval_ms);
        printf("      --retry-jitter-ms J   Additional random jitter in ms (default: %d)\n\n", default_retry_jitter_ms);
    }
    printf("      --timeout SEC         Socket timeout seconds (default: %d)\n", default_timeout_sec);
    printf("      --retries N           Retry count on transient errors (default: %d)\n", default_retries);
    printf("      --retry-interval-ms M Base interval between retries in ms (default: %d)\n", default_retry_interval_ms);
    printf("      --retry-jitter-ms J   Additional random jitter in ms (default: %d)\n\n", default_retry_jitter_ms);

    if (strcmp(lang, "zh") == 0) {
        printf("缓冲与缓存:\n");
        printf("  -b, --buffer-size BYTES   响应缓冲大小 (默认: %zu)\n", default_buffer);
        printf("  -d, --dns-cache N         DNS 缓存条目 (默认: %d)\n", default_dns_cache_size);
        printf("  -c, --conn-cache N        连接缓存条目 (默认: %d)\n", default_connection_cache_size);
        printf("  -T, --cache-timeout SEC   缓存TTL秒数 (默认: %d)\n\n", default_cache_timeout);
    } else {
        printf("Buffers & caches:\n");
        printf("  -b, --buffer-size BYTES   Response buffer size (default: %zu)\n", default_buffer);
        printf("  -d, --dns-cache N         DNS cache entries (default: %d)\n", default_dns_cache_size);
        printf("  -c, --conn-cache N        Connection cache entries (default: %d)\n", default_connection_cache_size);
        printf("  -T, --cache-timeout SEC   Cache TTL seconds (default: %d)\n\n", default_cache_timeout);
    }
    printf("  -b, --buffer-size BYTES   Response buffer size (default: %zu)\n", default_buffer);
    printf("  -d, --dns-cache N         DNS cache entries (default: %d)\n", default_dns_cache_size);
    printf("  -c, --conn-cache N        Connection cache entries (default: %d)\n", default_connection_cache_size);
    printf("  -T, --cache-timeout SEC   Cache TTL seconds (default: %d)\n\n", default_cache_timeout);

    if (strcmp(lang, "zh") == 0) {
        printf("条件输出引擎:\n");
        printf("  -g, --title PATTERN       标题前缀投影 (POSIX ERE, 不区分大小写)\n");
        printf("      --grep REGEX          正则过滤 (不区分大小写)\n");
        printf("      --grep-cs REGEX       正则过滤 (区分大小写)\n");
        printf("      --grep-line           行模式 (默认: 块模式)\n");
        printf("      --grep-block          块模式\n");
        printf("      --keep-cont           行模式下保留续行\n");
        printf("      --fold                单行折叠输出\n");
        printf("      --fold-sep STR        折叠分隔符 (默认: 空格)\n");
        printf("      --no-fold-upper       保留原大小写\n");
        printf("      --fold-unique         折叠去重 (去除重复字段)\n\n");
    } else {
        printf("Conditional output engine:\n");
        printf("  -g, --title PATTERN       Project selected headers (POSIX ERE, case-insensitive)\n");
        printf("      --grep REGEX          Filter lines or blocks by regex (case-insensitive)\n");
        printf("      --grep-cs REGEX       Case-sensitive grep\n");
        printf("      --grep-line           Line mode (default)\n");
        printf("      --grep-block          Block mode\n");
        printf("      --keep-cont           Keep continuation lines in line mode\n");
        printf("      --fold                Fold output: single line per query with selected fields\n");
        printf("      --fold-sep STR        Separator for folded output (default: space)\n");
        printf("      --no-fold-upper       Preserve original case in folded output (default: upper)\n");
        printf("      --fold-unique         De-duplicate tokens in folded output\n\n");
    }
    printf("  -g, --title PATTERN       Project selected headers (POSIX ERE, case-insensitive)\n");
    printf("      --grep REGEX          Filter lines or blocks by regex (case-insensitive)\n");
    printf("      --grep-cs REGEX       Case-sensitive grep\n");
    printf("      --grep-line           Line mode (default)\n");
    printf("      --grep-block          Block mode\n");
    printf("      --keep-cont           Keep continuation lines in line mode\n");
    printf("      --fold                Fold output: single line per query with selected fields\n");
    printf("      --fold-sep STR        Separator for folded output (default: space)\n");
    printf("      --no-fold-upper       Preserve original case in folded output (default: upper)\n\n");

    if (strcmp(lang, "zh") == 0) {
        printf("诊断/安全:\n");
        printf("      --security-log        安全事件日志\n");
        printf("      --debug-verbose       更详细调试输出 (附加缓存/重定向检查)\n");
        printf("      --selftest            运行内置自检后退出\n");
        printf("      --lang en|zh          设置帮助语言 (默认 en, 也可用 WHOIS_LANG 环境变量)\n\n");
    } else {
        printf("Diagnostics/Security:\n");
        printf("      --security-log        Enable security event logging to stderr\n");
        printf("      --debug-verbose       Extra verbose debug (cache/redirect instrumentation)\n");
        printf("      --selftest            Run internal self-tests and exit\n");
        printf("      --lang en|zh          Set help language (default en; WHOIS_LANG env also supported)\n\n");
    }
    printf("      --security-log        Enable security event logging to stderr\n\n");

    if (strcmp(lang, "zh") == 0) printf("示例:\n"); else printf("Examples:\n");
    printf("  %s --host apnic 103.89.208.0\n", program_name ? program_name : "whois");
    printf("  printf \"8.8.8.8\\n1.1.1.1\\n\" | %s -B -g 'netname|e-mail' --grep 'GOOGLE|CLOUDFLARE' --grep-line --fold\n",
        program_name ? program_name : "whois");
    printf("  %s --examples   # show more\n\n", program_name ? program_name : "whois");
}

void wc_meta_print_version(void) {
    printf("whois client %s\n", WHOIS_VERSION);
}

const char* wc_meta_version_string(void) {
    return WHOIS_VERSION;
}

void wc_meta_print_about(void) {
    printf("whois client %s - features & modules\n\n", WHOIS_VERSION);
    printf("Core features:\n");
    printf("- Smart redirects with loop guard; non-blocking connect, timeouts, and light retries.\n");
    printf("- Stable header/tail output contract for BusyBox pipelines.\n");
    printf("- Conditional output engine: -g title projection → --grep line/block → --fold.\n\n");
    printf("Modules:\n");
    printf("- wc_title: header projection and normalization.\n");
    printf("- wc_grep: POSIX ERE filtering (line/block, continuation handling).\n");
    printf("- wc_fold: folded single-line summary builder.\n");
    printf("- wc_output: header/tail formatting helpers.\n");
    printf("- wc_seclog: optional security event logging.\n");
    printf("- wc_opts: CLI parsing and feature wiring.\n");
    printf("- wc_meta: help/version/about/examples.\n\n");
    printf("Notes:\n");
    printf("- Batch mode: explicit -B or implicit when stdin is not a TTY and no positional query given.\n");
    printf("- Private IP is reported as such and marks authoritative as unknown.\n");
}

void wc_meta_print_examples(const char* program_name) {
    const char* prog = program_name ? program_name : "whois";
    printf("Extended examples (copy & try):\n\n");
    printf("# Single query with redirects\n");
    printf("%s 8.8.8.8\n\n", prog);
    printf("# Disable redirects and force APNIC\n");
    printf("%s --host apnic -Q 103.89.208.0\n\n", prog);
    printf("# Batch from stdin (explicit)\n");
    printf("printf \"8.8.8.8\\n1.1.1.1\\n\" | %s -B --host apnic\n\n", prog);
    printf("# Title projection + grep + fold\n");
    printf("%s -g 'netname|e-mail' --grep 'GOOGLE|CLOUDFLARE' --grep-line --fold 8.8.8.8\n\n", prog);
    printf("# Block mode grep on route/origin/descr\n");
    printf("%s --grep '^(route|origin|descr):' 1.1.1.1\n\n", prog);
    printf("# Preserve case in folded output\n");
    printf("%s --fold --fold-sep , --no-fold-upper 8.8.8.8\n\n", prog);
}
