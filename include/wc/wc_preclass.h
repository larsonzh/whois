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
