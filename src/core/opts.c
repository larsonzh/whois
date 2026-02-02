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
#include <getopt.h>
#include <unistd.h>
#include <ctype.h>

#include "wc/wc_defaults.h"
#include "wc/wc_opts.h"
#include "wc/wc_title.h"
#include "wc/wc_grep.h"
#include "wc/wc_seclog.h"
#include "wc/wc_net.h"
#include "wc/wc_selftest.h"

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
    o->cidr_fast_v4 = 0;
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
        o->selftest_workbuf = 0; // Initialize new selftest_workbuf flag default
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
    {"fold-unique", no_argument, 0, 1012},
    {"buffer-size", required_argument, 0, 'b'},
    {"retries", required_argument, 0, 'r'},
    {"timeout", required_argument, 0, 't'},
    {"retry-interval-ms", required_argument, 0, 'i'},
    {"retry-jitter-ms", required_argument, 0, 'J'},
    {"retry-all-addrs", no_argument, 0, 1111},
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
    {"cidr-strip", no_argument, 0, 1019},
    {"cidr-fast-v4", no_argument, 0, 1020},
    {"cidr-home-v4", no_argument, 0, 1021},
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
                if (o->fold_sep) { free((char*)o->fold_sep); o->fold_sep=NULL; }
                if (optarg && strcmp(optarg, "\\t") == 0) o->fold_sep = strdup("\t");
                else if (optarg && strcmp(optarg, "\\n") == 0) o->fold_sep = strdup("\n");
                else if (optarg && strcmp(optarg, "\\r") == 0) o->fold_sep = strdup("\r");
                else if (optarg && (strcmp(optarg, "\\s") == 0 || strcmp(optarg, "space") == 0)) o->fold_sep = strdup(" ");
                else o->fold_sep = strdup(optarg ? optarg : " ");
                if (!o->fold_sep) { fprintf(stderr,"Error: OOM parsing --fold-sep\n"); return 7; }
            } break;
            case 1008: o->fold_upper = 0; break;
            case 1009: o->security_log = 1; break;
            case 1012: o->fold_unique = 1; break;
            case 'B': explicit_batch_flag = 1; break;
            case 'Q': o->no_redirect = 1; break;
            case 'R': o->max_hops = atoi(optarg); if (o->max_hops<0){ fprintf(stderr,"Error: Invalid max redirects\n"); return 8;} break;
            case 'P': o->plain_mode = 1; break;
            case 1019: o->cidr_strip_query = 1; break;
            case 1020: o->cidr_fast_v4 = 1; break;
            case 1021: o->cidr_fast_v4 = 1; break;
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
            case 'd': o->dns_cache_size = atoi(optarg); if (o->dns_cache_size <=0){ fprintf(stderr,"Error: Invalid DNS cache size\n"); return 14;} if (o->dns_cache_size>20) o->dns_cache_size=20; break;
            case 'c': o->connection_cache_size = atoi(optarg); if (o->connection_cache_size <=0){ fprintf(stderr,"Error: Invalid connection cache size\n"); return 15;} if (o->connection_cache_size>10) o->connection_cache_size=10; break;
            case 'T': o->cache_timeout = atoi(optarg); if (o->cache_timeout <=0){ fprintf(stderr,"Error: Invalid cache timeout\n"); return 16;} break;
            default:
                // Unknown option handled by getopt_long already -> show help upstream
                return 17;
        }
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
}
