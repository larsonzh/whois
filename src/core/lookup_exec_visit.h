// SPDX-License-Identifier: MIT
// lookup_exec_visit.h - Visited host tracking helpers
#ifndef WC_LOOKUP_EXEC_VISIT_H_
#define WC_LOOKUP_EXEC_VISIT_H_

void wc_lookup_exec_mark_visited(const char* current_host,
                                 char** visited,
                                 int* visited_count);

#endif // WC_LOOKUP_EXEC_VISIT_H_
