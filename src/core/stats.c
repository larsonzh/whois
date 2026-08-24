// SPDX-License-Identifier: MIT
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) || defined(__MINGW32__)
#define strcasecmp _stricmp
#else
#include <strings.h>
#endif

#include "wc/wc_stats.h"

static int wc_stats_compare_duration(const void* lhs, const void* rhs)
{
    unsigned int left = *(const unsigned int*)lhs;
    unsigned int right = *(const unsigned int*)rhs;
    return (left > right) - (left < right);
}

static int wc_stats_host_is(const char* host,
                            const char* canonical,
                            const char* alias)
{
    if (!host || !*host)
        return 0;
    return strcasecmp(host, canonical) == 0 ||
        (alias && strcasecmp(host, alias) == 0);
}

static void wc_stats_record_rir(wc_stats_t* stats,
                                int success,
                                const char* host)
{
    if (!success) {
        stats->rir_error++;
    } else if (!host || !*host || strcasecmp(host, "unknown") == 0) {
        stats->rir_unknown++;
    } else if (wc_stats_host_is(host, "whois.iana.org", "iana")) {
        stats->rir_iana++;
    } else if (wc_stats_host_is(host, "whois.arin.net", "arin")) {
        stats->rir_arin++;
    } else if (wc_stats_host_is(host, "whois.ripe.net", "ripe")) {
        stats->rir_ripe++;
    } else if (wc_stats_host_is(host, "whois.apnic.net", "apnic")) {
        stats->rir_apnic++;
    } else if (wc_stats_host_is(host, "whois.lacnic.net", "lacnic")) {
        stats->rir_lacnic++;
    } else if (wc_stats_host_is(host, "whois.afrinic.net", "afrinic")) {
        stats->rir_afrinic++;
    } else if (wc_stats_host_is(host, "whois.verisign-grs.com", "verisign")) {
        stats->rir_verisign++;
    } else {
        stats->rir_other++;
    }
}

void wc_stats_init(wc_stats_t* stats)
{
    if (stats)
        memset(stats, 0, sizeof(*stats));
}

int wc_stats_prepare_next(wc_stats_t* stats)
{
    if (!stats)
        return WC_STATS_PREPARE_OOM;
    if (stats->duration_count >= WC_STATS_MAX_SAMPLES)
        return WC_STATS_PREPARE_LIMIT;
    if (stats->duration_count < stats->duration_capacity)
        return WC_STATS_PREPARE_OK;

    size_t next_capacity = stats->duration_capacity
        ? stats->duration_capacity * 2U : 64U;
    if (next_capacity > WC_STATS_MAX_SAMPLES)
        next_capacity = WC_STATS_MAX_SAMPLES;
    unsigned int* next = (unsigned int*)realloc(stats->durations_ms,
        next_capacity * sizeof(*next));
    if (!next)
        return WC_STATS_PREPARE_OOM;
    stats->durations_ms = next;
    stats->duration_capacity = next_capacity;
    return WC_STATS_PREPARE_OK;
}

void wc_stats_record(wc_stats_t* stats,
                     int success,
                     wc_stats_error_kind_t error_kind,
                     const char* authoritative_host,
                     unsigned int duration_ms)
{
    if (!stats || stats->duration_count >= stats->duration_capacity)
        return;

    stats->durations_ms[stats->duration_count++] = duration_ms;
    stats->total++;
    if (success) {
        stats->success++;
    } else {
        stats->error++;
        switch (error_kind) {
            case WC_STATS_ERROR_REJECTED:
                stats->error_rejected++;
                break;
            case WC_STATS_ERROR_INTERNAL:
                stats->error_internal++;
                break;
            case WC_STATS_ERROR_LOOKUP:
            case WC_STATS_ERROR_NONE:
            default:
                stats->error_lookup++;
                break;
        }
    }
    wc_stats_record_rir(stats, success, authoritative_host);
}

void wc_stats_calculate_percentiles(wc_stats_t* stats,
                                    unsigned int* p50_ms,
                                    unsigned int* p95_ms)
{
    unsigned int p50 = 0;
    unsigned int p95 = 0;
    if (!stats) {
        if (p50_ms)
            *p50_ms = 0;
        if (p95_ms)
            *p95_ms = 0;
        return;
    }
    if (stats->duration_count > 0) {
        qsort(stats->durations_ms, stats->duration_count,
            sizeof(*stats->durations_ms), wc_stats_compare_duration);
        size_t p50_index = (stats->duration_count - 1U) / 2U;
        size_t p95_index = (95U * stats->duration_count + 99U) / 100U - 1U;
        p50 = stats->durations_ms[p50_index];
        p95 = stats->durations_ms[p95_index];
    }
    if (p50_ms)
        *p50_ms = p50;
    if (p95_ms)
        *p95_ms = p95;
}

void wc_stats_render(wc_stats_t* stats)
{
    unsigned int p50 = 0;
    unsigned int p95 = 0;
    if (!stats)
        return;
    wc_stats_calculate_percentiles(stats, &p50, &p95);

    printf("stats_total=%" PRIu64
        "\tstats_success=%" PRIu64
        "\tstats_error=%" PRIu64
        "\tstats_error_lookup=%" PRIu64
        "\tstats_error_rejected=%" PRIu64
        "\tstats_error_internal=%" PRIu64
        "\tstats_rir_iana=%" PRIu64
        "\tstats_rir_arin=%" PRIu64
        "\tstats_rir_ripe=%" PRIu64
        "\tstats_rir_apnic=%" PRIu64
        "\tstats_rir_lacnic=%" PRIu64
        "\tstats_rir_afrinic=%" PRIu64
        "\tstats_rir_verisign=%" PRIu64
        "\tstats_rir_unknown=%" PRIu64
        "\tstats_rir_error=%" PRIu64
        "\tstats_rir_other=%" PRIu64
        "\tstats_duration_p50_ms=%u"
        "\tstats_duration_p95_ms=%u\n",
        stats->total, stats->success, stats->error,
        stats->error_lookup, stats->error_rejected, stats->error_internal,
        stats->rir_iana, stats->rir_arin, stats->rir_ripe,
        stats->rir_apnic, stats->rir_lacnic, stats->rir_afrinic,
        stats->rir_verisign, stats->rir_unknown, stats->rir_error,
        stats->rir_other, p50, p95);
}

void wc_stats_free(wc_stats_t* stats)
{
    if (!stats)
        return;
    free(stats->durations_ms);
    wc_stats_init(stats);
}