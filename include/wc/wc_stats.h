#ifndef WC_STATS_H
#define WC_STATS_H

#include <stddef.h>
#include <stdint.h>

#define WC_STATS_MAX_SAMPLES 1000000U

typedef enum wc_stats_error_kind {
    WC_STATS_ERROR_NONE = 0,
    WC_STATS_ERROR_LOOKUP,
    WC_STATS_ERROR_REJECTED,
    WC_STATS_ERROR_INTERNAL
} wc_stats_error_kind_t;

typedef struct wc_stats {
    uint64_t total;
    uint64_t success;
    uint64_t error;
    uint64_t error_lookup;
    uint64_t error_rejected;
    uint64_t error_internal;
    uint64_t rir_iana;
    uint64_t rir_arin;
    uint64_t rir_ripe;
    uint64_t rir_apnic;
    uint64_t rir_lacnic;
    uint64_t rir_afrinic;
    uint64_t rir_verisign;
    uint64_t rir_unknown;
    uint64_t rir_error;
    uint64_t rir_other;
    unsigned int* durations_ms;
    size_t duration_count;
    size_t duration_capacity;
} wc_stats_t;

enum {
    WC_STATS_PREPARE_OK = 0,
    WC_STATS_PREPARE_OOM = -1,
    WC_STATS_PREPARE_LIMIT = -2
};

void wc_stats_init(wc_stats_t* stats);
int wc_stats_prepare_next(wc_stats_t* stats);
void wc_stats_record(wc_stats_t* stats,
                     int success,
                     wc_stats_error_kind_t error_kind,
                     const char* authoritative_host,
                     unsigned int duration_ms);
void wc_stats_calculate_percentiles(wc_stats_t* stats,
                                    unsigned int* p50_ms,
                                    unsigned int* p95_ms);
void wc_stats_render(wc_stats_t* stats);
void wc_stats_free(wc_stats_t* stats);

#endif