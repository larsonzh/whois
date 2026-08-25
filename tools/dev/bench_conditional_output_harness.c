// SPDX-License-Identifier: MIT
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif

#include "wc/wc_fold.h"
#include "wc/wc_grep.h"
#include "wc/wc_title.h"
#include "wc/wc_workbuf.h"

void wc_runtime_register_title_cleanup(void) {}
void wc_runtime_register_grep_cleanup(void) {}
void wc_runtime_register_fold_cleanup(void) {}

typedef enum bench_scenario_e {
    BENCH_RAW,
    BENCH_TITLE,
    BENCH_GREP,
    BENCH_GREP_LINE,
    BENCH_GREP_LINE_CONT,
    BENCH_FOLD,
    BENCH_FOLD_UNIQUE,
    BENCH_BATCH
} bench_scenario_t;

#define BENCH_MAX_FIXTURES 32

static void usage(const char* program)
{
    fprintf(stderr,
        "Usage: %s --fixture PATH [...] --scenario "
        "raw|title|grep|grep-line|grep-line-cont|fold|fold-unique|batch "
        "[--iterations N] [--query TEXT] [--rir HOST]\n",
        program);
}

static char* read_fixture(const char* path)
{
    FILE* file = fopen(path, "rb");
    if (!file) {
        fprintf(stderr, "[BENCH][ERROR] cannot open fixture '%s': %s\n",
            path, strerror(errno));
        return NULL;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }
    long length = ftell(file);
    if (length < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }
    char* body = (char*)malloc((size_t)length + 1);
    if (!body) {
        fclose(file);
        return NULL;
    }
    size_t bytes_read = fread(body, 1, (size_t)length, file);
    fclose(file);
    if (bytes_read != (size_t)length) {
        free(body);
        return NULL;
    }
    body[bytes_read] = '\0';
    return body;
}

static int parse_scenario(const char* value, bench_scenario_t* scenario)
{
    if (strcmp(value, "raw") == 0) *scenario = BENCH_RAW;
    else if (strcmp(value, "title") == 0) *scenario = BENCH_TITLE;
    else if (strcmp(value, "grep") == 0) *scenario = BENCH_GREP;
    else if (strcmp(value, "grep-line") == 0) *scenario = BENCH_GREP_LINE;
    else if (strcmp(value, "grep-line-cont") == 0) *scenario = BENCH_GREP_LINE_CONT;
    else if (strcmp(value, "fold") == 0) *scenario = BENCH_FOLD;
    else if (strcmp(value, "fold-unique") == 0) *scenario = BENCH_FOLD_UNIQUE;
    else if (strcmp(value, "batch") == 0) *scenario = BENCH_BATCH;
    else return 0;
    return 1;
}

static int configure_scenario(bench_scenario_t scenario)
{
    wc_title_set_enabled(0);
    wc_grep_set_enabled(0);
    wc_fold_set_unique(0);
    if (scenario == BENCH_TITLE) {
        wc_title_set_enabled(1);
        return wc_title_parse_patterns(
            "netrange|inetnum|inet6num|netname|orgname|org-name|country|descr|origin|route") >= 0;
    }
    if (scenario == BENCH_GREP || scenario == BENCH_GREP_LINE ||
        scenario == BENCH_GREP_LINE_CONT) {
        wc_grep_set_enabled(1);
        wc_grep_set_line_mode(scenario != BENCH_GREP);
        wc_grep_set_keep_continuation(scenario != BENCH_GREP_LINE);
        return wc_grep_compile(
            "^(netrange|inetnum|inet6num|netname|orgname|org-name|country|descr|origin|route):",
            0) >= 0;
    }
    if (scenario == BENCH_FOLD_UNIQUE)
        wc_fold_set_unique(1);
    return 1;
}

static char* normalize_fixture(const char* body, wc_workbuf_t* wb)
{
    size_t length = strlen(body);
    char* output = wc_workbuf_reserve(wb, length, "normalize_fixture");
    size_t output_pos = 0;
    for (size_t input_pos = 0; input_pos < length; ++input_pos) {
        if (body[input_pos] == '\r') {
            output[output_pos++] = '\n';
            if (input_pos + 1 < length && body[input_pos + 1] == '\n')
                ++input_pos;
        } else {
            output[output_pos++] = body[input_pos];
        }
    }
    output[output_pos] = '\0';
    return output;
}

static char* run_scenario(bench_scenario_t scenario,
        const char* query,
        const char* rir,
        const char* body,
        wc_workbuf_t* filter_wb,
        wc_workbuf_t* fold_wb)
{
    char* filtered = normalize_fixture(body, filter_wb);
    if (!filtered)
        return NULL;
    if (scenario == BENCH_TITLE)
        filtered = wc_title_filter_response_wb(filtered, filter_wb);
    else if (scenario == BENCH_GREP || scenario == BENCH_GREP_LINE ||
        scenario == BENCH_GREP_LINE_CONT)
        filtered = wc_grep_filter_wb(filtered, filter_wb);
    if (scenario == BENCH_FOLD || scenario == BENCH_FOLD_UNIQUE)
        return wc_fold_build_line_wb(filtered, query, rir, " ", 1, fold_wb);
    return filtered;
}

int main(int argc, char** argv)
{
#if defined(_WIN32)
    if (_setmode(_fileno(stdout), _O_BINARY) == -1) {
        fprintf(stderr, "[BENCH][ERROR] cannot set stdout binary mode\n");
        return 1;
    }
#endif
    const char* fixture_paths[BENCH_MAX_FIXTURES];
    size_t fixture_count = 0;
    const char* scenario_name = NULL;
    const char* query = "benchmark.example";
    const char* rir = "whois.example.test";
    long iterations = 1;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--fixture") == 0 && i + 1 < argc) {
            if (fixture_count == BENCH_MAX_FIXTURES) {
                fprintf(stderr, "[BENCH][ERROR] too many fixtures\n");
                return 2;
            }
            fixture_paths[fixture_count++] = argv[++i];
        }
        else if (strcmp(argv[i], "--scenario") == 0 && i + 1 < argc)
            scenario_name = argv[++i];
        else if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc)
            iterations = strtol(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--query") == 0 && i + 1 < argc)
            query = argv[++i];
        else if (strcmp(argv[i], "--rir") == 0 && i + 1 < argc)
            rir = argv[++i];
        else {
            usage(argv[0]);
            return 2;
        }
    }
    if (fixture_count == 0 || !scenario_name || iterations < 1) {
        usage(argv[0]);
        return 2;
    }

    bench_scenario_t scenario;
    if (!parse_scenario(scenario_name, &scenario)) {
        usage(argv[0]);
        return 2;
    }
    if (!configure_scenario(scenario)) {
        fprintf(stderr, "[BENCH][ERROR] scenario setup failed: %s\n", scenario_name);
        return 1;
    }

    if (scenario != BENCH_BATCH && fixture_count != 1) {
        fprintf(stderr, "[BENCH][ERROR] multiple fixtures require scenario=batch\n");
        return 2;
    }
    char* bodies[BENCH_MAX_FIXTURES] = {0};
    for (size_t fixture_index = 0; fixture_index < fixture_count; ++fixture_index) {
        bodies[fixture_index] = read_fixture(fixture_paths[fixture_index]);
        if (!bodies[fixture_index]) {
            fprintf(stderr, "[BENCH][ERROR] fixture read failed: %s\n",
                fixture_paths[fixture_index]);
            for (size_t free_index = 0; free_index < fixture_index; ++free_index)
                free(bodies[free_index]);
            return 1;
        }
    }

    wc_workbuf_t filter_wb;
    wc_workbuf_t fold_wb;
    wc_workbuf_init(&filter_wb);
    wc_workbuf_init(&fold_wb);

    char* output = NULL;
    size_t output_bytes = 0;
    wc_workbuf_stats_reset();
    for (long iteration = 0; iteration < iterations; ++iteration) {
        output_bytes = 0;
        for (size_t fixture_index = 0; fixture_index < fixture_count; ++fixture_index) {
            output = run_scenario(scenario, query, rir, bodies[fixture_index],
                &filter_wb, &fold_wb);
            if (!output) {
                fprintf(stderr, "[BENCH][ERROR] scenario execution failed\n");
                for (size_t free_index = 0; free_index < fixture_count; ++free_index)
                    free(bodies[free_index]);
                wc_workbuf_free(&fold_wb);
                wc_workbuf_free(&filter_wb);
                wc_grep_free();
                wc_title_free();
                return 1;
            }
            size_t current_bytes = strlen(output);
            output_bytes += current_bytes;
            if (iteration == iterations - 1 && current_bytes > 0 &&
                fwrite(output, 1, current_bytes, stdout) != current_bytes) {
                fprintf(stderr, "[BENCH][ERROR] stdout write failed\n");
                return 1;
            }
        }
    }

    wc_workbuf_stats_t stats = wc_workbuf_stats_snapshot();
    fprintf(stderr,
        "[BENCH] scenario=%s iterations=%ld output_bytes=%zu "
        "reserves=%zu grow=%zu max_request=%zu max_cap=%zu max_view=%zu\n",
        scenario_name, iterations, output_bytes, stats.reserves,
        stats.grow_events, stats.max_request, stats.max_cap,
        stats.max_view_size);

    for (size_t fixture_index = 0; fixture_index < fixture_count; ++fixture_index)
        free(bodies[fixture_index]);
    wc_workbuf_free(&fold_wb);
    wc_workbuf_free(&filter_wb);
    wc_grep_free();
    wc_title_free();
    return 0;
}