// wc_preclass.h - Preclass helpers shared by query flow modules
#ifndef WC_PRECLASS_H_
#define WC_PRECLASS_H_

#ifdef __cplusplus
extern "C" {
#endif

// Returns 1 only when csv is exactly one token equal to "default"
// (case-insensitive, surrounding whitespace allowed).
int wc_preclass_csv_is_default_marker(const char* csv);

// Classify one normalized IP literal into preclass fields.
// Non-IP values leave outputs untouched.
void wc_preclass_classify_ip(const char* normalized,
                             const char** family,
                             const char** cls,
                             const char** rir,
                             const char** reason,
                             const char** confidence);

// Unified decision fields for PRECLASS log lines.
typedef struct wc_preclass_decision_fields {
    const char* action;
    const char* action_source;
    const char* match_layer;
    const char* fallback_reason;
    const char* input_label;
    int route_change;
} wc_preclass_decision_fields_t;

// Resolves trial/action decision fields into a stable, log-ready view.
void wc_preclass_resolve_decision_fields(const char* query,
        const char* decision_action,
        int route_change,
        int preclass_disabled,
        wc_preclass_decision_fields_t* out_fields);

// Normalizes observation fields into stable code/rank values used by PRECLASS logs.
void wc_preclass_observation_codes(const char* reason,
                                   const char* confidence,
                                   const char** reason_code,
                                   const char** reason_key,
                                   const char** confidence_code,
                                   int* confidence_rank);

#ifdef __cplusplus
}
#endif

#endif // WC_PRECLASS_H_
