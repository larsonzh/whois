// SPDX-License-Identifier: MIT
// wc_opts: command-line options parsing module

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32) || defined(__MINGW32__)
#include <io.h>
#else
#include <getopt.h>
#include <unistd.h>
#endif
#include <ctype.h>

#include "wc/wc_strings.h"
#include "wc/wc_dns.h" /* 13B-2 A proxy literal validation */

#if defined(_WIN32) || defined(__MINGW32__)
/* Minimal getopt shim for Windows/MinGW hosts (no system getopt.h). */
#define no_argument 0
#define required_argument 1
struct option {
    const char* name;
    int has_arg;
    int* flag;
    int val;
};
int optind = 1;
char* optarg = NULL;
static int wc_opts_getopt_long_shim(int argc,
    char* const argv[],
    const char* shortopts,
    const struct option* longopts,
    int* idx)
{
    static const char* short_cursor = NULL;
    const char* arg;
    const struct option* opt;
    const char* short_spec;
    char short_name;

    optarg = NULL;
    if (short_cursor && *short_cursor) {
        short_name = *short_cursor++;
        short_spec = shortopts ? strchr(shortopts, short_name) : NULL;
        if (!short_spec) {
            short_cursor = NULL;
            return '?';
        }
        if (short_spec[1] == ':') {
            if (*short_cursor != '\0')
                optarg = (char*)short_cursor;
            else if (optind < argc)
                optarg = argv[optind++];
            else {
                short_cursor = NULL;
                return '?';
            }
            short_cursor = NULL;
        }
        else if (*short_cursor == '\0') {
            short_cursor = NULL;
        }
        return (unsigned char)short_name;
    }

    if (optind >= argc)
        return -1;
    arg = argv[optind];
    if (!arg || arg[0] != '-' || arg[1] == '\0') {
        int next_option = optind + 1;
        int option_span = 1;
        char** mutable_argv = (char**)argv;
        char* option_arg;
        char* option_value = NULL;

        while (next_option < argc) {
            const char* candidate = argv[next_option];
            if (candidate && strcmp(candidate, "--") == 0)
                return -1;
            if (candidate && candidate[0] == '-' && candidate[1] != '\0')
                break;
            next_option++;
        }
        if (next_option >= argc)
            return -1;

        option_arg = argv[next_option];
        if (option_arg[1] == '-' && !strchr(option_arg + 2, '=')) {
            const struct option* candidate_opt;
            for (candidate_opt = longopts;
                    candidate_opt && candidate_opt->name; ++candidate_opt) {
                if (strcmp(option_arg + 2, candidate_opt->name) == 0) {
                    if (candidate_opt->has_arg == required_argument)
                        option_span = 2;
                    break;
                }
            }
        } else if (option_arg[1] != '-' && option_arg[2] == '\0') {
            const char* candidate_spec = shortopts
                ? strchr(shortopts, option_arg[1]) : NULL;
            if (candidate_spec && candidate_spec[1] == ':')
                option_span = 2;
        }
        if (option_span == 2) {
            if (next_option + 1 >= argc)
                option_span = 1;
            else
                option_value = argv[next_option + 1];
        }

        memmove(&mutable_argv[optind + option_span], &mutable_argv[optind],
            (size_t)(next_option - optind) * sizeof(argv[0]));
        mutable_argv[optind] = option_arg;
        if (option_span == 2)
            mutable_argv[optind + 1] = option_value;
        return wc_opts_getopt_long_shim(argc, argv, shortopts, longopts, idx);
    }
    if (strcmp(arg, "--") == 0) {
        optind++;
        return -1;
    }

    if (arg[1] != '-') {
        short_cursor = arg + 1;
        optind++;
        return wc_opts_getopt_long_shim(argc, argv, shortopts, longopts, idx);
    }

    arg += 2;
    for (opt = longopts; opt && opt->name; ++opt) {
        size_t n = strlen(opt->name);
        if (strncmp(arg, opt->name, n) != 0)
            continue;
        if (arg[n] != '\0' && arg[n] != '=')
            continue;
        if (idx)
            *idx = (int)(opt - longopts);
        optind++;
        if (opt->has_arg) {
            if (arg[n] == '=')
                optarg = (char*)(arg + n + 1);
            else if (optind < argc)
                optarg = argv[optind++];
            else
                return '?';
        }
        return opt->val;
    }
    optind++;
    return '?';
}
#define getopt_long(argc, argv, opts, longopts, idx) wc_opts_getopt_long_shim(argc, argv, opts, longopts, idx)
#endif

#include "wc/wc_defaults.h"
#include "wc/wc_opts.h"
#include "wc/wc_title.h"
#include "wc/wc_grep.h"
#include "wc/wc_seclog.h"
#include "wc/wc_net.h"
#include "wc/wc_selftest.h"
#include "wc/wc_pick.h"

static void wc_opts_set_dns_mode_slot(wc_dns_family_mode_t* slot,
    int* cur_priority,
    wc_dns_family_mode_t mode,
    int new_priority,
    int* mark_set) {
    if (!slot || !cur_priority) return;
    if (new_priority >= *cur_priority) {
        *slot = mode;
        *cur_priority = new_priority;
        if (mark_set) *mark_set = 1;
    }
}

static void wc_opts_set_dns_mode(wc_opts_t* opts, int* cur_priority, wc_dns_family_mode_t mode, int new_priority) {
    if (!opts) return;
    wc_opts_set_dns_mode_slot(&opts->dns_family_mode, cur_priority, mode, new_priority, NULL);
}

static int wc_opts_parse_dns_mode_value(const char* value, wc_dns_family_mode_t* out_mode) {
    if (!value || !*value || !out_mode) return -1;
    if (strcasecmp(value, "interleave-v4-first") == 0) {
        *out_mode = WC_DNS_FAMILY_MODE_INTERLEAVE_V4_FIRST;
    } else if (strcasecmp(value, "interleave-v6-first") == 0) {
        *out_mode = WC_DNS_FAMILY_MODE_INTERLEAVE_V6_FIRST;
    } else if (strcasecmp(value, "seq-v4-then-v6") == 0 || strcasecmp(value, "v4-then-v6") == 0) {
        *out_mode = WC_DNS_FAMILY_MODE_SEQUENTIAL_V4_THEN_V6;
    } else if (strcasecmp(value, "seq-v6-then-v4") == 0 || strcasecmp(value, "v6-then-v4") == 0) {
        *out_mode = WC_DNS_FAMILY_MODE_SEQUENTIAL_V6_THEN_V4;
    } else if (strcasecmp(value, "ipv4-only-block") == 0 || strcasecmp(value, "v4-only-block") == 0) {
        *out_mode = WC_DNS_FAMILY_MODE_IPV4_ONLY_BLOCK;
    } else if (strcasecmp(value, "ipv6-only-block") == 0 || strcasecmp(value, "v6-only-block") == 0) {
        *out_mode = WC_DNS_FAMILY_MODE_IPV6_ONLY_BLOCK;
    } else {
        return -1;
    }
    return 0;
}

static char* wc_opts_trim_local(char* s) {
    if (!s) return s;
    while (*s && isspace((unsigned char)*s)) s++;
    if (!*s) return s;
    char* end = s + strlen(s) - 1;
    while (end >= s && isspace((unsigned char)*end)) {
        *end-- = '\0';
    }
    return s;
}

static void wc_opts_apply_late_plain(wc_opts_t* o,
    int argc,
    char* const* argv,
    int start_index)
{
    if (!o || !argv)
        return;
    if (start_index < 0)
        start_index = 0;
    for (int i = start_index; i < argc; ++i) {
        const char* arg = argv[i];
        if (!arg)
            continue;
        if (strcmp(arg, "--") == 0)
            break;
        if (strcmp(arg, "-P") == 0 || strcmp(arg, "--plain") == 0) {
            o->plain_mode = 1;
        }
    }
}

static int wc_opts_parse_rir_pref_value(const char* value, wc_rir_ip_pref_t* out) {
    if (!value || !*value || !out) return -1;
    if (strcasecmp(value, "v4") == 0 || strcasecmp(value, "ipv4") == 0) {
        *out = WC_RIR_IP_PREF_V4;
        return 0;
    }
    if (strcasecmp(value, "v6") == 0 || strcasecmp(value, "ipv6") == 0) {
        *out = WC_RIR_IP_PREF_V6;
        return 0;
    }
    return -1;
}

static int wc_opts_apply_rir_pref(wc_opts_t* o, const char* key, const char* value) {
    if (!o || !key || !*key || !value || !*value) return -1;
    wc_rir_ip_pref_t pref;
    if (wc_opts_parse_rir_pref_value(value, &pref) != 0) return -1;
    if (strcasecmp(key, "iana") == 0) o->rir_pref_iana = pref;
    else if (strcasecmp(key, "arin") == 0) o->rir_pref_arin = pref;
    else if (strcasecmp(key, "ripe") == 0) o->rir_pref_ripe = pref;
    else if (strcasecmp(key, "apnic") == 0) o->rir_pref_apnic = pref;
    else if (strcasecmp(key, "lacnic") == 0) o->rir_pref_lacnic = pref;
    else if (strcasecmp(key, "afrinic") == 0) o->rir_pref_afrinic = pref;
    else if (strcasecmp(key, "verisign") == 0) o->rir_pref_verisign = pref;
    else return -1;
    return 0;
}

static int wc_opts_parse_rir_pref_list(wc_opts_t* o, const char* value) {
    if (!o || !value || !*value) return -1;
    char* copy = strdup(value);
    if (!copy) return -1;
    int rc = 0;
    char* token = strtok(copy, ",");
    while (token) {
        char* item = wc_opts_trim_local(token);
        if (!item || !*item) { token = strtok(NULL, ","); continue; }
        char* eq = strchr(item, '=');
        if (!eq) { rc = -1; break; }
        *eq = '\0';
        char* key = wc_opts_trim_local(item);
        char* val = wc_opts_trim_local(eq + 1);
        if (!key || !*key || !val || !*val) { rc = -1; break; }
        if (wc_opts_apply_rir_pref(o, key, val) != 0) { rc = -1; break; }
        token = strtok(NULL, ",");
    }
    free(copy);
    return rc;
}

// Local helpers ----------------------------------------------------------------
void wc_opts_proxy_clear(wc_proxy_config_t* proxy)
{
    volatile unsigned char* cursor;
    size_t index;
    if (!proxy) return;
    cursor = (volatile unsigned char*)proxy;
    for (index = 0; index < sizeof(*proxy); ++index) cursor[index] = 0;
}

static int wc_opts_proxy_copy(char* dst, size_t capacity, const char* src)
{
    size_t length;
    if (!dst || capacity == 0 || !src) return 0;
    length = strlen(src);
    if (length >= capacity) return 0;
    memcpy(dst, src, length + 1);
    return 1;
}

static int wc_opts_proxy_hex(unsigned char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static int wc_opts_proxy_percent_well_formed(const char* text)
{
    const unsigned char* cursor = (const unsigned char*)text;
    if (!cursor) return 0;
    while (*cursor) {
        if (*cursor == '%') {
            if (!cursor[1] || !cursor[2] || wc_opts_proxy_hex(cursor[1]) < 0 ||
                wc_opts_proxy_hex(cursor[2]) < 0) return 0;
            cursor += 3;
        } else {
            ++cursor;
        }
    }
    return 1;
}

static int wc_opts_proxy_decode(char* dst, size_t capacity, const char* src)
{
    size_t used = 0;
    const unsigned char* cursor = (const unsigned char*)src;
    if (!dst || capacity == 0 || !cursor) return 0;
    while (*cursor) {
        unsigned char value = *cursor++;
        if (value == '%') {
            int high = wc_opts_proxy_hex(cursor[0]);
            int low = wc_opts_proxy_hex(cursor[1]);
            if (high < 0 || low < 0) return 0;
            value = (unsigned char)((high << 4) | low);
            cursor += 2;
        }
        if (value == 0 || value < 0x20 || value == 0x7f || used + 1 >= capacity) return 0;
        dst[used++] = (char)value;
    }
    dst[used] = '\0';
    return used != 0;
}

static int wc_opts_proxy_has_rir_override(const wc_opts_t* opts)
{
    return opts->rir_pref_iana != WC_RIR_IP_PREF_UNSET ||
        opts->rir_pref_arin != WC_RIR_IP_PREF_UNSET ||
        opts->rir_pref_ripe != WC_RIR_IP_PREF_UNSET ||
        opts->rir_pref_apnic != WC_RIR_IP_PREF_UNSET ||
        opts->rir_pref_lacnic != WC_RIR_IP_PREF_UNSET ||
        opts->rir_pref_afrinic != WC_RIR_IP_PREF_UNSET ||
        opts->rir_pref_verisign != WC_RIR_IP_PREF_UNSET;
}

int wc_opts_proxy_resolve(const wc_opts_t* opts, const wc_proxy_env_t* env, wc_proxy_config_t* out)
{
    const char* url = NULL;
    const char* authority;
    const char* scheme_end;
    const char* at;
    const char* host_begin;
    const char* port_text = NULL;
    const char* dedicated_user = env ? env->whois_proxy_user : NULL;
    const char* dedicated_password = env ? env->whois_proxy_password : NULL;
    const char* no_proxy_value = NULL;
    char authority_buffer[512];
    char userinfo[257];
    char host[256];
    char* colon;
    char* port_end = NULL;
    size_t authority_length;
    long port = 0;
    int from_cli = 0;
    int literal;

    if (!opts || !out) return 0;
    wc_opts_proxy_clear(out);
    out->scheme = WC_PROXY_SCHEME_DIRECT;
    out->family = WC_PROXY_FAMILY_AUTO;
    out->source = WC_PROXY_SOURCE_NONE;
    out->proxy_env_enabled = opts->proxy_env ? 1 : 0;
    out->allow_insecure_auth = opts->proxy_allow_insecure_auth ? 1 : 0;

    if ((dedicated_user == NULL) != (dedicated_password == NULL) ||
        (dedicated_user && (!*dedicated_user || !*dedicated_password))) {
        fprintf(stderr, "Error: WHOIS_PROXY_USER and WHOIS_PROXY_PASSWORD must both be non-empty\n");
        goto fail;
    }

    if (opts->proxy_url) {
        if (!*opts->proxy_url) { fprintf(stderr, "Error: --proxy requires a non-empty URL\n"); goto fail; }
        url = opts->proxy_url;
        out->source = WC_PROXY_SOURCE_CLI;
        from_cli = 1;
    } else if (env && env->whois_proxy && *env->whois_proxy) {
        url = env->whois_proxy;
        out->source = WC_PROXY_SOURCE_WHOIS_PROXY;
    } else if (opts->proxy_env && env && env->all_proxy && *env->all_proxy) {
        url = env->all_proxy;
        out->source = WC_PROXY_SOURCE_ALL_PROXY;
    } else if (opts->proxy_env && env && env->all_proxy_lower && *env->all_proxy_lower) {
        url = env->all_proxy_lower;
        out->source = WC_PROXY_SOURCE_ALL_PROXY_LOWER;
    }
    if (!url) return 1;
    out->configured = 1;
    out->routing_enabled = 0;
    if (opts->proxy_env && env) {
        no_proxy_value = (env->no_proxy && *env->no_proxy) ? env->no_proxy : env->no_proxy_lower;
        if (no_proxy_value && *no_proxy_value &&
            !wc_opts_proxy_copy(out->no_proxy, sizeof(out->no_proxy), no_proxy_value)) {
            fprintf(stderr, "Error: NO_PROXY value is too long\n");
            goto fail;
        }
    }

    if (!wc_opts_proxy_percent_well_formed(url)) { fprintf(stderr, "Error: malformed percent escape in proxy URL\n"); goto fail; }
    if (strchr(url, '?') || strchr(url, '#')) { fprintf(stderr, "Error: proxy URL query/fragment is not allowed\n"); goto fail; }
    scheme_end = strstr(url, "://");
    if (!scheme_end || scheme_end == url) { fprintf(stderr, "Error: proxy URL must be absolute\n"); goto fail; }
    if ((size_t)(scheme_end - url) == 4 && strncasecmp(url, "http", 4) == 0) {
        out->scheme = WC_PROXY_SCHEME_HTTP;
        port = 8080;
    } else if ((size_t)(scheme_end - url) == 6 && strncasecmp(url, "socks5", 6) == 0) {
        out->scheme = WC_PROXY_SCHEME_SOCKS5;
        port = 1080;
    } else if ((size_t)(scheme_end - url) == 7 && strncasecmp(url, "socks5h", 7) == 0) {
        out->scheme = WC_PROXY_SCHEME_SOCKS5H;
        port = 1080;
    } else {
        fprintf(stderr, "Error: unsupported proxy scheme\n");
        goto fail;
    }

    authority = scheme_end + 3;
    if (!*authority || strchr(authority, '/')) { fprintf(stderr, "Error: proxy URL must contain authority only\n"); goto fail; }
    authority_length = strlen(authority);
    if (authority_length >= sizeof(authority_buffer)) { fprintf(stderr, "Error: proxy authority is too long\n"); goto fail; }
    memcpy(authority_buffer, authority, authority_length + 1);
    at = strchr(authority_buffer, '@');
    if (at && strchr(at + 1, '@')) { fprintf(stderr, "Error: proxy URL contains multiple userinfo separators\n"); goto fail; }
    host_begin = authority_buffer;
    if (at) {
        size_t userinfo_length = (size_t)(at - authority_buffer);
        if (from_cli) { fprintf(stderr, "Error: CLI proxy URL userinfo is forbidden\n"); goto fail; }
        if (dedicated_user) { fprintf(stderr, "Error: proxy URL userinfo conflicts with dedicated credentials\n"); goto fail; }
        if (userinfo_length == 0 || userinfo_length >= sizeof(userinfo)) { fprintf(stderr, "Error: invalid proxy URL userinfo\n"); goto fail; }
        memcpy(userinfo, authority_buffer, userinfo_length);
        userinfo[userinfo_length] = '\0';
        colon = strchr(userinfo, ':');
        if (!colon) { fprintf(stderr, "Error: proxy URL userinfo requires user and password\n"); goto fail; }
        *colon++ = '\0';
        if (!wc_opts_proxy_decode(out->username, sizeof(out->username), userinfo) ||
            !wc_opts_proxy_decode(out->password, sizeof(out->password), colon)) {
            fprintf(stderr, "Error: proxy URL userinfo must decode to non-empty credentials\n");
            goto fail;
        }
        out->has_credentials = 1;
        host_begin = at + 1;
    }

    if (*host_begin == '[') {
        const char* close = strchr(host_begin + 1, ']');
        size_t host_length;
        if (!close || close == host_begin + 1) { fprintf(stderr, "Error: invalid bracketed proxy IPv6 literal\n"); goto fail; }
        host_length = (size_t)(close - host_begin - 1);
        if (host_length >= sizeof(host)) { fprintf(stderr, "Error: proxy host is too long\n"); goto fail; }
        memcpy(host, host_begin + 1, host_length);
        host[host_length] = '\0';
        if (close[1] == ':') port_text = close + 2;
        else if (close[1] != '\0') { fprintf(stderr, "Error: invalid proxy authority suffix\n"); goto fail; }
        if (!wc_dns_is_ip_literal(host) || !strchr(host, ':')) { fprintf(stderr, "Error: brackets require an IPv6 literal\n"); goto fail; }
    } else {
        const char* first_colon = strchr(host_begin, ':');
        const char* last_colon = strrchr(host_begin, ':');
        size_t host_length;
        if (first_colon && first_colon != last_colon) { fprintf(stderr, "Error: IPv6 proxy literals must use brackets\n"); goto fail; }
        if (last_colon) {
            host_length = (size_t)(last_colon - host_begin);
            port_text = last_colon + 1;
        } else {
            host_length = strlen(host_begin);
        }
        if (host_length == 0 || host_length >= sizeof(host)) { fprintf(stderr, "Error: invalid proxy host\n"); goto fail; }
        memcpy(host, host_begin, host_length);
        host[host_length] = '\0';
    }
    if (strchr(host, '%') || strpbrk(host, " \t\r\n")) { fprintf(stderr, "Error: invalid proxy host\n"); goto fail; }
    if (port_text) {
        const unsigned char* digit = (const unsigned char*)port_text;
        if (!*digit) { fprintf(stderr, "Error: proxy port is empty\n"); goto fail; }
        while (*digit) { if (!isdigit(*digit++)) { fprintf(stderr, "Error: proxy port must be numeric\n"); goto fail; } }
        port = strtol(port_text, &port_end, 10);
        if (!port_end || *port_end || port < 1 || port > 65535) { fprintf(stderr, "Error: proxy port is out of range\n"); goto fail; }
    }
    if (!wc_opts_proxy_copy(out->endpoint_host, sizeof(out->endpoint_host), host)) { fprintf(stderr, "Error: proxy host is too long\n"); goto fail; }
    out->endpoint_port = (int)port;

    if (!opts->proxy_family || !*opts->proxy_family || strcasecmp(opts->proxy_family, "auto") == 0) out->family = WC_PROXY_FAMILY_AUTO;
    else if (strcasecmp(opts->proxy_family, "v4") == 0) out->family = WC_PROXY_FAMILY_V4;
    else if (strcasecmp(opts->proxy_family, "v6") == 0) out->family = WC_PROXY_FAMILY_V6;
    else { fprintf(stderr, "Error: invalid --proxy-family (expected auto|v4|v6)\n"); goto fail; }
    literal = wc_dns_is_ip_literal(host);
    if (literal && ((out->family == WC_PROXY_FAMILY_V4 && strchr(host, ':')) ||
        (out->family == WC_PROXY_FAMILY_V6 && !strchr(host, ':')))) {
        fprintf(stderr, "Error: proxy-family conflicts with numeric proxy endpoint\n");
        goto fail;
    }

    if (dedicated_user) {
        if (!wc_opts_proxy_copy(out->username, sizeof(out->username), dedicated_user) ||
            !wc_opts_proxy_copy(out->password, sizeof(out->password), dedicated_password)) {
            fprintf(stderr, "Error: dedicated proxy credentials are too long\n");
            goto fail;
        }
        out->has_credentials = 1;
    }
    if (out->scheme == WC_PROXY_SCHEME_HTTP && out->has_credentials && !out->allow_insecure_auth) {
        fprintf(stderr, "Error: cleartext HTTP proxy credentials require --proxy-allow-insecure-auth\n");
        goto fail;
    }
    if (out->scheme == WC_PROXY_SCHEME_SOCKS5H &&
        (opts->ipv4_only || opts->ipv6_only || opts->dns_family_mode_set ||
         opts->dns_family_mode_first_set || opts->dns_family_mode_next_set ||
         opts->no_dns_known_fallback || opts->no_dns_force_ipv4_fallback ||
         opts->no_iana_pivot || opts->dns_no_fallback || wc_opts_proxy_has_rir_override(opts))) {
        fprintf(stderr, "Error: socks5h conflicts with target-family, fallback, or RIR override controls\n");
        goto fail;
    }
    out->routing_enabled = (out->scheme == WC_PROXY_SCHEME_HTTP);
    return 1;

fail:
    wc_opts_proxy_clear(out);
    return 0;
}

static size_t parse_size_with_unit_local(const char* str) {
    if (!str || !*str) return 0;
    char* end = NULL;
    unsigned long long base = strtoull(str, &end, 10);
    if (!end || !*end) return (size_t)base;
    unsigned long long mult = 1;
    if (end[0] == 'K' || end[0] == 'k') mult = 1024ULL;
    else if (end[0] == 'M' || end[0] == 'm') mult = 1024ULL * 1024ULL;
    else if (end[0] == 'G' || end[0] == 'g') mult = 1024ULL * 1024ULL * 1024ULL;
    if (end[1] != '\0') return 0; // trailing junk
    unsigned long long total = base * mult;
    return (size_t)total;
}

void wc_opts_init_defaults(wc_opts_t* o) {
    memset(o, 0, sizeof(*o));
    o->port = WC_DEFAULT_WHOIS_PORT;
    o->retries = WC_DEFAULT_MAX_RETRIES;
    o->timeout_sec = 5;
    o->retry_interval_ms = 300;
    o->retry_jitter_ms = 300;
    o->retry_all_addrs = 0;
    o->app_retry_rate_limit = 2;
    o->app_retry_interval_ms = 2500;
    o->pacing_disable = 0;
    o->pacing_interval_ms = 60;
    o->pacing_jitter_ms = 40;
    o->pacing_backoff_factor = 2;
    o->pacing_max_ms = 400;
    o->retry_metrics = 0;
    o->buffer_size = 524288; // 512K default
    o->dns_cache_size = 10;
    o->connection_cache_size = 5;
    o->cache_timeout = 300;
    o->batch_interval_ms = 0;
    o->batch_jitter_ms = 0;
    o->max_hops = 6;
    o->fold_upper = 1;
    o->cidr_strip_query = 0;
    o->cidr_erx_recheck = 1;
    o->preclass_first_hop_enable = 1;
    o->preclass_early_converge_enable = 1;
    o->prefer_ipv4 = 0; // default preference ordering (IPv6 then IPv4)
    o->prefer_ipv6 = 1;
    o->ip_pref_mode = WC_IP_PREF_MODE_FORCE_V6_FIRST;
    o->rir_pref_iana = WC_RIR_IP_PREF_UNSET;
    o->rir_pref_arin = WC_RIR_IP_PREF_UNSET;
    o->rir_pref_ripe = WC_RIR_IP_PREF_UNSET;
    o->rir_pref_apnic = WC_RIR_IP_PREF_UNSET;
    o->rir_pref_lacnic = WC_RIR_IP_PREF_UNSET;
    o->rir_pref_afrinic = WC_RIR_IP_PREF_UNSET;
    o->rir_pref_verisign = WC_RIR_IP_PREF_UNSET;
    o->dns_family_mode = WC_DNS_FAMILY_MODE_SEQUENTIAL_V6_THEN_V4;
    o->dns_family_mode_first = WC_DNS_FAMILY_MODE_INTERLEAVE_V6_FIRST;
    o->dns_family_mode_next = WC_DNS_FAMILY_MODE_SEQUENTIAL_V6_THEN_V4;
    o->dns_family_mode_first_set = 0;
    o->dns_family_mode_next_set = 0;
    o->dns_family_mode_set = 0;
    o->dns_neg_ttl = 10; // default negative DNS cache TTL (seconds)
    // DNS resolver defaults (Phase 1)
    o->dns_addrconfig = 1;
    o->dns_retry = 3;
    o->dns_retry_interval_ms = 100;
    o->dns_max_candidates = 12;
    o->max_host_addrs = 0; // 0 = unbounded per-host address attempts
    o->dns_backoff_window_ms = 10000;
    o->dns_append_known_ips = 0;
    // Fallback toggles default to enabled behavior (off means enabled)
    o->no_dns_known_fallback = 0;
    o->no_dns_force_ipv4_fallback = 0;
    o->no_iana_pivot = 0;
    o->dns_no_fallback = 0;
    o->cache_counter_sampling = 0;
    o->disable_address_preclass = 0;
    o->preclass_action_enable = 0;
    o->preclass_action_tier = 0;
    o->preclass_action_list = NULL;
    o->step47_trial_enable = 0;
    o->step47_trial_scope = 0;
    o->step47_early_unknown_enable = 0;
    o->step47_early_unknown_list = NULL;
    o->selftest_workbuf = 0; // Initialize new selftest_workbuf flag default
    o->no_body = 0;
    o->print_meta = 0;
    o->print_chain = 0;
    o->stats = 0;
    o->pick_keys = NULL;
    o->pick_mode = WC_PICK_MODE_FIRST;
    o->pick_mode_seen = 0;
    o->show_non_auth_body = 0;
    o->show_post_marker_body = 0;
    o->hide_failure_body = 0;
    o->proxy_url = NULL;
    o->proxy_env = 0;
    o->proxy_family = "auto";
    o->proxy_allow_insecure_auth = 0;
}

static struct option wc_long_options[] = {
    {"host", required_argument, 0, 'h'},
    {"port", required_argument, 0, 'p'},
    {"title", required_argument, 0, 'g'},
    {"grep", required_argument, 0, 1000},
    {"grep-cs", required_argument, 0, 1001},
    {"grep-line", no_argument, 0, 1002},
    {"keep-continuation-lines", no_argument, 0, 1003},
    {"grep-block", no_argument, 0, 1004},
    {"no-keep-continuation-lines", no_argument, 0, 1005},
    {"fold", no_argument, 0, 1006},
    {"fold-sep", required_argument, 0, 1007},
    {"no-fold-upper", no_argument, 0, 1008},
    {"security-log", no_argument, 0, 1009},
    {"disable-address-preclass", no_argument, 0, 1312},
    {"enable-preclass-actions", no_argument, 0, 1317},
    {"preclass-action-tier", required_argument, 0, 1318},
    {"preclass-action-list", required_argument, 0, 1319},
    {"enable-step47-trial", no_argument, 0, 1313},
    {"step47-trial-scope", required_argument, 0, 1314},
    {"enable-step47-early-unknown", no_argument, 0, 1315},
    {"step47-early-unknown-list", required_argument, 0, 1316},
    {"enable-preclass-first-hop", no_argument, 0, 1320},
    {"enable-preclass-early-converge", no_argument, 0, 1321},
    {"fold-unique", no_argument, 0, 1012},
    {"no-body", no_argument, 0, 1322},
    {"print-meta", no_argument, 0, 1323},
    {"print-chain", no_argument, 0, 1324},
    {"pick", required_argument, 0, 1325},
    {"pick-mode", required_argument, 0, 1326},
    {"stats", no_argument, 0, 1327},
    {"buffer-size", required_argument, 0, 'b'},
    {"retries", required_argument, 0, 'r'},
    {"timeout", required_argument, 0, 't'},
    {"retry-interval-ms", required_argument, 0, 'i'},
    {"retry-jitter-ms", required_argument, 0, 'J'},
    {"retry-all-addrs", no_argument, 0, 1111},
    {"rate-limit-retries", required_argument, 0, 1310},
    {"rate-limit-retry-interval-ms", required_argument, 0, 1311},
    {"dns-cache", required_argument, 0, 'd'},
    {"conn-cache", required_argument, 0, 'c'},
    {"cache-timeout", required_argument, 0, 'T'},
    {"max-redirects", required_argument, 0, 'R'},
    {"max-hops", required_argument, 0, 'R'},
    {"no-redirect", no_argument, 0, 'Q'},
    {"batch", no_argument, 0, 'B'},
    {"batch-interval-ms", required_argument, 0, 1301},
    {"batch-jitter-ms", required_argument, 0, 1302},
    {"plain", no_argument, 0, 'P'},
    {"show-non-auth-body", no_argument, 0, 1303},
    {"show-post-marker-body", no_argument, 0, 1304},
    {"hide-failure-body", no_argument, 0, 1305},
    {"cidr-strip", no_argument, 0, 1019},
    {"debug", no_argument, 0, 'D'},
    {"list", no_argument, 0, 'l'},
    {"version", no_argument, 0, 'v'},
    {"help", no_argument, 0, 'H'},
    {"about", no_argument, 0, 1010},
    {"examples", no_argument, 0, 1011},
    {"selftest", no_argument, 0, 1013},
    {"debug-verbose", no_argument, 0, 1014},
    // New pacing CLI (connect-level retry pacing unified with existing env mechanism)
    {"pacing-disable", no_argument, 0, 1100},
    {"pacing-interval-ms", required_argument, 0, 1101},
    {"pacing-jitter-ms", required_argument, 0, 1102},
    {"pacing-backoff-factor", required_argument, 0, 1103},
    {"pacing-max-ms", required_argument, 0, 1104},
    {"retry-metrics", no_argument, 0, 1105},
    {"selftest-fail-first-attempt", no_argument, 0, 1106},
    {"selftest-inject-empty", no_argument, 0, 1107},
    {"selftest-grep", no_argument, 0, 1108},
    {"selftest-seclog", no_argument, 0, 1109},
    {"selftest-workbuf", no_argument, 0, 1112},
    {"selftest-dns-negative", no_argument, 0, 1110},
    {"selftest-blackhole-iana", no_argument, 0, 1113},
    {"selftest-blackhole-arin", no_argument, 0, 1114},
    {"selftest-force-iana-pivot", no_argument, 0, 1115},
    {"selftest-force-suspicious", required_argument, 0, 1116},
    {"selftest-force-private", required_argument, 0, 1117},
    {"selftest-registry", no_argument, 0, 1118},
    // DNS / IP family preference
    {"ipv4-only", no_argument, 0, 1200},
    {"ipv6-only", no_argument, 0, 1201},
    {"prefer-ipv4", no_argument, 0, 1202},
    {"prefer-ipv6", no_argument, 0, 1203},
    {"prefer-ipv4-ipv6", no_argument, 0, 1215},
    {"prefer-ipv6-ipv4", no_argument, 0, 1216},
    {"rir-ip-pref", required_argument, 0, 1224},
    {"dns-family-mode-first", required_argument, 0, 1220},
    {"dns-family-mode-next", required_argument, 0, 1221},
    {"dns-family-mode", required_argument, 0, 1218},
    {"dns-neg-ttl", required_argument, 0, 1204},
    {"no-dns-neg-cache", no_argument, 0, 1205},
    {"no-dns-addrconfig", no_argument, 0, 1206},
    {"dns-retry", required_argument, 0, 1207},
    {"dns-retry-interval-ms", required_argument, 0, 1208},
    {"dns-max-candidates", required_argument, 0, 1209},
    {"max-host-addrs", required_argument, 0, 1219},
    {"dns-backoff-window-ms", required_argument, 0, 1222},
    {"dns-append-known-ips", no_argument, 0, 1223},
    {"no-known-ip-fallback", no_argument, 0, 1210},
    {"no-force-ipv4-fallback", no_argument, 0, 1211},
    {"no-iana-pivot", no_argument, 0, 1212},
    {"dns-cache-stats", no_argument, 0, 1213},
    {"dns-no-fallback", no_argument, 0, 1214},
    {"cache-counter-sampling", no_argument, 0, 1217},
    {"proxy", required_argument, 0, 1328},
    {"proxy-env", no_argument, 0, 1329},
    {"proxy-family", required_argument, 0, 1330},
    {"proxy-allow-insecure-auth", no_argument, 0, 1331},
    {"batch-strategy", required_argument, 0, 1300},
    /* language option removed */
    {0,0,0,0}
};

int wc_opts_parse(int argc, char* argv[], wc_opts_t* o) {
    if (!o) return 1;
    wc_opts_init_defaults(o);

    int opt, option_index = 0;
    int explicit_batch_flag = 0;
    int dns_family_mode_priority = 0; // 0: default, 1: prefer, 2: strict prefer-ip*-ip*, 3: forced single-stack
    int dns_family_mode_first_priority = 0;
    int dns_family_mode_next_priority = 0;

    // ensure default fold separator
    if (!o->fold_sep) {
        o->fold_sep = strdup(" ");
        if (!o->fold_sep) { fprintf(stderr, "OOM initializing fold separator\n"); return 2; }
    }

    while ((opt = getopt_long(argc, argv, "h:p:g:b:r:t:i:J:d:c:T:R:QBPDlvH", wc_long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h': o->host = optarg; break;
            case 'p':
                o->port = atoi(optarg);
                if (o->port <=0 || o->port>65535) { fprintf(stderr,"Error: Invalid port\n"); return 3; }
                break;
            case 'g':
                wc_title_free();
                wc_title_set_enabled(1);
                if (wc_title_parse_patterns(optarg) < 0) { wc_title_free(); return 4; }
                o->title_pat = optarg;
                break;
            case 1000: // --grep (ci)
                if (wc_grep_compile(optarg,0) < 0) return 5;
                o->grep_pat = optarg; o->grep_case_sensitive = 0; break;
            case 1001: // --grep-cs
                if (wc_grep_compile(optarg,1) < 0) return 6;
                o->grep_pat = optarg; o->grep_case_sensitive = 1; break;
            case 1002: wc_grep_set_line_mode(1); o->grep_mode_block = 0; break;
            case 1003: wc_grep_set_keep_continuation(1); o->keep_continuation = 1; break;
            case 1004: wc_grep_set_line_mode(0); o->grep_mode_block = 1; break;
            case 1005: wc_grep_set_keep_continuation(0); o->keep_continuation = 0; break;
            case 1006: o->fold = 1; break;
            case 1007: {
                o->fold_modifier_seen = 1;
                if (o->fold_sep) { free((char*)o->fold_sep); o->fold_sep=NULL; }
                if (optarg && strcmp(optarg, "\\t") == 0) o->fold_sep = strdup("\t");
                else if (optarg && strcmp(optarg, "\\n") == 0) o->fold_sep = strdup("\n");
                else if (optarg && strcmp(optarg, "\\r") == 0) o->fold_sep = strdup("\r");
                else if (optarg && (strcmp(optarg, "\\s") == 0 || strcmp(optarg, "space") == 0)) o->fold_sep = strdup(" ");
                else o->fold_sep = strdup(optarg ? optarg : " ");
                if (!o->fold_sep) { fprintf(stderr,"Error: OOM parsing --fold-sep\n"); return 7; }
            } break;
            case 1008: o->fold_modifier_seen = 1; o->fold_upper = 0; break;
            case 1009: o->security_log = 1; break;
            case 1312: o->disable_address_preclass = 1; break;
            case 1317: o->preclass_action_enable = 1; break;
            case 1318:
                if (strcasecmp(optarg, "r0") == 0) {
                    o->preclass_action_tier = 0;
                } else if (strcasecmp(optarg, "r1") == 0) {
                    o->preclass_action_tier = 1;
                } else {
                    fprintf(stderr, "Error: Invalid --preclass-action-tier (expected r0|r1)\n");
                    return 33;
                }
                break;
            case 1319:
                if (!optarg || !*optarg) {
                    fprintf(stderr, "Error: Invalid --preclass-action-list (expected CSV queries)\n");
                    return 34;
                }
                o->preclass_action_list = optarg;
                break;
            case 1313: o->step47_trial_enable = 1; break;
            case 1314:
                if (strcasecmp(optarg, "minimal") == 0) {
                    o->step47_trial_scope = 0;
                } else if (strcasecmp(optarg, "reserved") == 0) {
                    o->step47_trial_scope = 1;
                } else if (strcasecmp(optarg, "all") == 0) {
                    o->step47_trial_scope = 2;
                } else {
                    fprintf(stderr, "Error: Invalid --step47-trial-scope (expected minimal|reserved|all)\n");
                    return 24;
                }
                break;
            case 1315: o->step47_early_unknown_enable = 1; break;
            case 1316:
                if (!optarg || !*optarg) {
                    fprintf(stderr, "Error: Invalid --step47-early-unknown-list (expected CSV queries)\n");
                    return 32;
                }
                o->step47_early_unknown_list = optarg;
                break;
            case 1320: o->preclass_first_hop_enable = 1; break;
            case 1321: o->preclass_early_converge_enable = 1; break;
            case 1012: o->fold_modifier_seen = 1; o->fold_unique = 1; break;
            case 1322: o->no_body = 1; break;
            case 1323: o->print_meta = 1; break;
            case 1324: o->print_chain = 1; break;
            case 1327: o->stats = 1; break;
            case 1328: o->proxy_url = optarg; break;
            case 1329: o->proxy_env = 1; break;
            case 1330: o->proxy_family = optarg; break;
            case 1331: o->proxy_allow_insecure_auth = 1; break;
            case 1325: {
                char* parsed = NULL;
                if (wc_pick_parse_keys(optarg, &parsed) != 0)
                    return 36;
                free(o->pick_keys);
                o->pick_keys = parsed;
            } break;
            case 1326:
                o->pick_mode_seen = 1;
                if (strcasecmp(optarg, "first") == 0)
                    o->pick_mode = WC_PICK_MODE_FIRST;
                else if (strcasecmp(optarg, "join") == 0)
                    o->pick_mode = WC_PICK_MODE_JOIN;
                else {
                    fprintf(stderr, "Error: Invalid --pick-mode (expected first|join)\n");
                    return 36;
                }
                break;
            case 'B': explicit_batch_flag = 1; break;
            case 'Q': o->no_redirect = 1; break;
            case 'R': o->max_hops = atoi(optarg); if (o->max_hops<0){ fprintf(stderr,"Error: Invalid max redirects\n"); return 8;} break;
            case 'P': o->plain_mode = 1; break;
            case 1303: o->show_non_auth_body = 1; break;
            case 1304: o->show_post_marker_body = 1; break;
            case 1305: o->hide_failure_body = 1; break;
            case 1019: o->cidr_strip_query = 1; break;
            case 'D': o->debug = 1; break;
            case 'l': o->show_servers = 1; break;
            case 'v': o->show_version = 1; break;
            case 'H': o->show_help = 1; break;
            case 1010: o->show_about = 1; break;
            case 1011: o->show_examples = 1; break;
            case 1013: o->show_selftest = 1; break;
            case 1014: o->debug_verbose = 1; break;
            case 1100: // --pacing-disable
                o->pacing_disable = 1; break;
            case 1101: { // --pacing-interval-ms
                long v = strtol(optarg, NULL, 10);
                if (v <= 0 || v > 60000) { fprintf(stderr, "Error: Invalid --pacing-interval-ms\n"); return 18; }
                o->pacing_interval_ms = (int)v;
            } break;
            case 1102: { // --pacing-jitter-ms
                long v = strtol(optarg, NULL, 10);
                if (v < 0 || v > 60000) { fprintf(stderr, "Error: Invalid --pacing-jitter-ms\n"); return 19; }
                o->pacing_jitter_ms = (int)v;
            } break;
            case 1103: { // --pacing-backoff-factor
                long v = strtol(optarg, NULL, 10);
                if (v < 1 || v > 16) { fprintf(stderr, "Error: Invalid --pacing-backoff-factor (1..16)\n"); return 20; }
                o->pacing_backoff_factor = (int)v;
            } break;
            case 1104: { // --pacing-max-ms
                long v = strtol(optarg, NULL, 10);
                if (v < 1 || v > 60000) { fprintf(stderr, "Error: Invalid --pacing-max-ms\n"); return 21; }
                o->pacing_max_ms = (int)v;
            } break;
            case 1105: o->retry_metrics = 1; break;
            case 1106: o->selftest_fail_first = 1; break;
            case 1107: o->selftest_inject_empty = 1; break;
            case 1108: o->selftest_grep = 1; break;
            case 1109: o->selftest_seclog = 1; break;
            case 1112: o->selftest_workbuf = 1; break;
            case 1110: o->selftest_dns_negative = 1; break;
            case 1113: o->selftest_blackhole_iana = 1; break;
            case 1114: o->selftest_blackhole_arin = 1; break;
            case 1115: o->selftest_force_iana_pivot = 1; break;
            case 1116: o->selftest_force_suspicious = optarg; break;
            case 1117: o->selftest_force_private = optarg; break;
            case 1118: o->selftest_registry = 1; break;
            case 1111: o->retry_all_addrs = 1; break;
            case 1200:
                o->ipv4_only = 1;
                o->ipv6_only = o->prefer_ipv4 = o->prefer_ipv6 = 0;
                o->ip_pref_mode = WC_IP_PREF_MODE_FORCE_V4_FIRST;
                wc_opts_set_dns_mode_slot(&o->dns_family_mode, &dns_family_mode_priority, WC_DNS_FAMILY_MODE_IPV4_ONLY_BLOCK, 4, NULL);
                wc_opts_set_dns_mode_slot(&o->dns_family_mode_first, &dns_family_mode_first_priority, WC_DNS_FAMILY_MODE_IPV4_ONLY_BLOCK, 4, &o->dns_family_mode_first_set);
                wc_opts_set_dns_mode_slot(&o->dns_family_mode_next, &dns_family_mode_next_priority, WC_DNS_FAMILY_MODE_IPV4_ONLY_BLOCK, 4, &o->dns_family_mode_next_set);
                o->dns_family_mode_set = 1;
                break;
            case 1201:
                o->ipv6_only = 1;
                o->ipv4_only = o->prefer_ipv4 = o->prefer_ipv6 = 0;
                o->ip_pref_mode = WC_IP_PREF_MODE_FORCE_V6_FIRST;
                wc_opts_set_dns_mode_slot(&o->dns_family_mode, &dns_family_mode_priority, WC_DNS_FAMILY_MODE_IPV6_ONLY_BLOCK, 4, NULL);
                wc_opts_set_dns_mode_slot(&o->dns_family_mode_first, &dns_family_mode_first_priority, WC_DNS_FAMILY_MODE_IPV6_ONLY_BLOCK, 4, &o->dns_family_mode_first_set);
                wc_opts_set_dns_mode_slot(&o->dns_family_mode_next, &dns_family_mode_next_priority, WC_DNS_FAMILY_MODE_IPV6_ONLY_BLOCK, 4, &o->dns_family_mode_next_set);
                o->dns_family_mode_set = 1;
                break;
            case 1202:
                o->prefer_ipv4 = 1;
                o->prefer_ipv6 = o->ipv4_only = o->ipv6_only = 0;
                o->ip_pref_mode = WC_IP_PREF_MODE_FORCE_V4_FIRST;
                wc_opts_set_dns_mode_slot(&o->dns_family_mode_first, &dns_family_mode_first_priority, WC_DNS_FAMILY_MODE_INTERLEAVE_V4_FIRST, 1, NULL);
                wc_opts_set_dns_mode_slot(&o->dns_family_mode_next, &dns_family_mode_next_priority, WC_DNS_FAMILY_MODE_SEQUENTIAL_V4_THEN_V6, 1, NULL);
                wc_opts_set_dns_mode(o, &dns_family_mode_priority, WC_DNS_FAMILY_MODE_INTERLEAVE_V4_FIRST, 1);
                break;
            case 1203:
                o->prefer_ipv6 = 1;
                o->prefer_ipv4 = o->ipv4_only = o->ipv6_only = 0;
                o->ip_pref_mode = WC_IP_PREF_MODE_FORCE_V6_FIRST;
                wc_opts_set_dns_mode_slot(&o->dns_family_mode_first, &dns_family_mode_first_priority, WC_DNS_FAMILY_MODE_INTERLEAVE_V6_FIRST, 1, NULL);
                wc_opts_set_dns_mode_slot(&o->dns_family_mode_next, &dns_family_mode_next_priority, WC_DNS_FAMILY_MODE_SEQUENTIAL_V6_THEN_V4, 1, NULL);
                wc_opts_set_dns_mode(o, &dns_family_mode_priority, WC_DNS_FAMILY_MODE_INTERLEAVE_V6_FIRST, 1);
                break;
            case 1215:
                o->prefer_ipv4 = 1;
                o->prefer_ipv6 = o->ipv4_only = o->ipv6_only = 0;
                o->ip_pref_mode = WC_IP_PREF_MODE_V4_THEN_V6;
                wc_opts_set_dns_mode_slot(&o->dns_family_mode_first, &dns_family_mode_first_priority, WC_DNS_FAMILY_MODE_INTERLEAVE_V4_FIRST, 2, NULL);
                wc_opts_set_dns_mode_slot(&o->dns_family_mode_next, &dns_family_mode_next_priority, WC_DNS_FAMILY_MODE_SEQUENTIAL_V6_THEN_V4, 2, NULL);
                wc_opts_set_dns_mode(o, &dns_family_mode_priority, WC_DNS_FAMILY_MODE_SEQUENTIAL_V4_THEN_V6, 2);
                break;
            case 1216:
                o->prefer_ipv6 = 1;
                o->prefer_ipv4 = o->ipv4_only = o->ipv6_only = 0;
                o->ip_pref_mode = WC_IP_PREF_MODE_V6_THEN_V4;
                wc_opts_set_dns_mode_slot(&o->dns_family_mode_first, &dns_family_mode_first_priority, WC_DNS_FAMILY_MODE_INTERLEAVE_V6_FIRST, 2, NULL);
                wc_opts_set_dns_mode_slot(&o->dns_family_mode_next, &dns_family_mode_next_priority, WC_DNS_FAMILY_MODE_SEQUENTIAL_V4_THEN_V6, 2, NULL);
                wc_opts_set_dns_mode(o, &dns_family_mode_priority, WC_DNS_FAMILY_MODE_SEQUENTIAL_V6_THEN_V4, 2);
                break;
            case 1218: {
                wc_dns_family_mode_t parsed;
                if (!optarg || !*optarg) { fprintf(stderr, "Error: --dns-family-mode requires a value\n"); return 26; }
                if (wc_opts_parse_dns_mode_value(optarg, &parsed) != 0) {
                    fprintf(stderr, "Error: Unknown --dns-family-mode '%s' (use interleave-v4-first|interleave-v6-first|seq-v4-then-v6|seq-v6-then-v4|ipv4-only-block|ipv6-only-block)\n", optarg);
                    return 26;
                }
                wc_opts_set_dns_mode(o, &dns_family_mode_priority, parsed, 3);
                o->dns_family_mode_set = 1;
            } break;
            case 1224: {
                if (!optarg || !*optarg) { fprintf(stderr, "Error: --rir-ip-pref requires a value\n"); return 31; }
                if (wc_opts_parse_rir_pref_list(o, optarg) != 0) {
                    fprintf(stderr, "Error: Invalid --rir-ip-pref '%s' (use arin=v4,ripe=v6,apnic=v4,...)\n", optarg);
                    return 31;
                }
            } break;
            case 1220: {
                wc_dns_family_mode_t parsed;
                if (!optarg || !*optarg) { fprintf(stderr, "Error: --dns-family-mode-first requires a value\n"); return 26; }
                if (wc_opts_parse_dns_mode_value(optarg, &parsed) != 0) {
                    fprintf(stderr, "Error: Unknown --dns-family-mode-first '%s'\n", optarg);
                    return 26;
                }
                wc_opts_set_dns_mode_slot(&o->dns_family_mode_first, &dns_family_mode_first_priority, parsed, 4, &o->dns_family_mode_first_set);
            } break;
            case 1221: {
                wc_dns_family_mode_t parsed;
                if (!optarg || !*optarg) { fprintf(stderr, "Error: --dns-family-mode-next requires a value\n"); return 26; }
                if (wc_opts_parse_dns_mode_value(optarg, &parsed) != 0) {
                    fprintf(stderr, "Error: Unknown --dns-family-mode-next '%s'\n", optarg);
                    return 26;
                }
                wc_opts_set_dns_mode_slot(&o->dns_family_mode_next, &dns_family_mode_next_priority, parsed, 4, &o->dns_family_mode_next_set);
            } break;
            case 1204: {
                long v = strtol(optarg, NULL, 10);
                if (v < 1 || v > 3600) { fprintf(stderr, "Error: Invalid --dns-neg-ttl (1..3600)\n"); return 22; }
                o->dns_neg_ttl = (int)v;
            } break;
            case 1205: o->dns_neg_cache_disable = 1; break;
            case 1206: o->dns_addrconfig = 0; break;
            case 1207: {
                long v = strtol(optarg, NULL, 10);
                if (v < 1 || v > 10) { fprintf(stderr, "Error: Invalid --dns-retry (1..10)\n"); return 23; }
                o->dns_retry = (int)v;
            } break;
            case 1208: {
                long v = strtol(optarg, NULL, 10);
                if (v < 0 || v > 5000) { fprintf(stderr, "Error: Invalid --dns-retry-interval-ms (0..5000)\n"); return 24; }
                o->dns_retry_interval_ms = (int)v;
            } break;
            case 1209: {
                long v = strtol(optarg, NULL, 10);
                if (v < 1 || v > 64) { fprintf(stderr, "Error: Invalid --dns-max-candidates (1..64)\n"); return 25; }
                o->dns_max_candidates = (int)v;
            } break;
            case 1219: {
                long v = strtol(optarg, NULL, 10);
                if (v < 1 || v > 64) { fprintf(stderr, "Error: Invalid --max-host-addrs (1..64)\n"); return 27; }
                o->max_host_addrs = (int)v;
            } break;
            case 1222: {
                long v = strtol(optarg, NULL, 10);
                if (v < 0 || v > 600000) { fprintf(stderr, "Error: Invalid --dns-backoff-window-ms (0..600000)\n"); return 28; }
                o->dns_backoff_window_ms = (int)v;
            } break;
            case 1223: o->dns_append_known_ips = 1; break;
            case 1210: o->no_dns_known_fallback = 1; break;
            case 1211: o->no_dns_force_ipv4_fallback = 1; break;
            case 1212: o->no_iana_pivot = 1; break;
            case 1213: o->dns_cache_stats = 1; break;
            case 1214: o->dns_no_fallback = 1; break;
            case 1217: o->cache_counter_sampling = 1; break;
            case 1300: o->batch_strategy = optarg; break;
            case 1301: {
                long v = strtol(optarg, NULL, 10);
                if (v < 0 || v > 600000) { fprintf(stderr, "Error: Invalid --batch-interval-ms (0..600000)\n"); return 29; }
                o->batch_interval_ms = (int)v;
            } break;
            case 1302: {
                long v = strtol(optarg, NULL, 10);
                if (v < 0 || v > 600000) { fprintf(stderr, "Error: Invalid --batch-jitter-ms (0..600000)\n"); return 30; }
                o->batch_jitter_ms = (int)v;
            } break;
            /* language option removed */
            case 'b': {
                size_t new_size = parse_size_with_unit_local(optarg);
                if (new_size == 0) { fprintf(stderr,"Error: Invalid buffer size '%s'\n", optarg); return 9; }
                if (new_size > 1024ULL*1024ULL*1024ULL) new_size = 1024ULL*1024ULL*1024ULL;
                if (new_size < 1024) new_size = 1024;
                o->buffer_size = new_size;
            } break;
            case 'r': o->retries = atoi(optarg); if (o->retries < 0){ fprintf(stderr,"Error: Invalid retry count\n"); return 10;} break;
            case 't': o->timeout_sec = atoi(optarg); if (o->timeout_sec <=0){ fprintf(stderr,"Error: Invalid timeout\n"); return 11;} break;
            case 'i': o->retry_interval_ms = atoi(optarg); if (o->retry_interval_ms <0){ fprintf(stderr,"Error: Invalid retry interval\n"); return 12;} break;
            case 'J': o->retry_jitter_ms = atoi(optarg); if (o->retry_jitter_ms <0){ fprintf(stderr,"Error: Invalid retry jitter\n"); return 13;} break;
            case 1310: {
                long v = strtol(optarg, NULL, 10);
                if (v < 0 || v > 10) { fprintf(stderr, "Error: Invalid --rate-limit-retries (0..10)\n"); return 32; }
                o->app_retry_rate_limit = (int)v;
            } break;
            case 1311: {
                long v = strtol(optarg, NULL, 10);
                if (v < 0 || v > 600000) { fprintf(stderr, "Error: Invalid --rate-limit-retry-interval-ms (0..600000)\n"); return 33; }
                o->app_retry_interval_ms = (int)v;
            } break;
            case 'd': o->dns_cache_size = atoi(optarg); if (o->dns_cache_size <=0){ fprintf(stderr,"Error: Invalid DNS cache size\n"); return 14;} if (o->dns_cache_size>20) o->dns_cache_size=20; break;
            case 'c': o->connection_cache_size = atoi(optarg); if (o->connection_cache_size <=0){ fprintf(stderr,"Error: Invalid connection cache size\n"); return 15;} if (o->connection_cache_size>10) o->connection_cache_size=10; break;
            case 'T': o->cache_timeout = atoi(optarg); if (o->cache_timeout <=0){ fprintf(stderr,"Error: Invalid cache timeout\n"); return 16;} break;
            default:
                // Unknown option handled by getopt_long already -> show help upstream
                return 17;
        }
    }

    {
        wc_proxy_env_t proxy_env = {
            getenv("WHOIS_PROXY"),
            getenv("ALL_PROXY"),
            getenv("all_proxy"),
            getenv("WHOIS_PROXY_USER"),
            getenv("WHOIS_PROXY_PASSWORD"),
            getenv("NO_PROXY"),
            getenv("no_proxy")
        };
        if (!wc_opts_proxy_resolve(o, &proxy_env, &o->proxy)) return 37;
        if (o->proxy.configured && !o->proxy.routing_enabled) {
            wc_opts_proxy_clear(&o->proxy);
            fprintf(stderr, "Error: Configured proxy scheme is not available in the HTTP CONNECT build\n");
            return 37;
        }
    }

    // Preserve late -P/--plain handling for options appended after the query.
    wc_opts_apply_late_plain(o, argc, argv, optind + 1);

    if (o->print_meta && o->plain_mode) {
        fprintf(stderr, "Error: --print-meta cannot be combined with --plain\n");
        return 35;
    }
    if (o->print_chain && o->plain_mode) {
        fprintf(stderr, "Error: --print-chain cannot be combined with --plain\n");
        return 35;
    }
    if (o->pick_mode_seen && !o->pick_keys) {
        fprintf(stderr, "Error: --pick-mode requires --pick\n");
        return 35;
    }
    if (o->pick_keys && o->plain_mode) {
        fprintf(stderr, "Error: --pick cannot be combined with --plain\n");
        return 35;
    }
    if (o->stats && o->plain_mode) {
        fprintf(stderr, "Error: --stats cannot be combined with --plain\n");
        return 35;
    }
    if (o->no_body && o->plain_mode) {
        fprintf(stderr, "Error: --no-body cannot be combined with --plain\n");
        return 35;
    }
    if (o->no_body && (o->fold || o->fold_modifier_seen)) {
        fprintf(stderr, "Error: --no-body cannot be combined with fold options\n");
        return 35;
    }

    // Auto batch mode if stdin is not a TTY and -B not explicitly supplied
    if (explicit_batch_flag || !isatty(fileno(stdin))) {
        o->batch_mode = 1;
    }
    o->explicit_batch = explicit_batch_flag;

    // Apply security log module enable now
    wc_seclog_set_enabled(o->security_log);
    return 0;
}

void wc_opts_free(wc_opts_t* o) {
    if (!o) return;
    if (o->fold_sep) { free((char*)o->fold_sep); o->fold_sep = NULL; }
    free(o->pick_keys); o->pick_keys = NULL;
    wc_opts_proxy_clear(&o->proxy);
}
