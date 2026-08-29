// SPDX-License-Identifier: MIT
// Portable case-insensitive string comparison helpers.

#ifndef WC_STRINGS_H_
#define WC_STRINGS_H_

#include <string.h>

#if defined(_WIN32) || defined(__MINGW32__)
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#else
#include <strings.h>
#endif

#endif // WC_STRINGS_H_