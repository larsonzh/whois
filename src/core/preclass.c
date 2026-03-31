#include <ctype.h>
#include <string.h>
#if !defined(_WIN32) && !defined(__MINGW32__)
#include <strings.h>
#endif

#if defined(_WIN32) || defined(__MINGW32__)
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include "wc/wc_preclass.h"
#include "wc/wc_server.h"

int wc_preclass_csv_is_default_marker(const char* csv)
{
	const char* p;
	int saw_token = 0;

	if (!csv)
		return 0;

	p = csv;
	while (*p) {
		const char* start;
		const char* end;
		size_t tlen;

		while (*p == ',' || isspace((unsigned char)*p))
			++p;
		if (!*p)
			break;

		start = p;
		while (*p && *p != ',')
			++p;
		end = p;

		while (end > start && isspace((unsigned char)end[-1]))
			--end;
		tlen = (size_t)(end - start);
		if (tlen == 0)
			continue;

		if (saw_token)
			return 0;
		if (tlen != 7 || strncasecmp(start, "default", 7) != 0)
			return 0;
		saw_token = 1;
	}

	return saw_token;
}

static void wc_preclass_set_allocated_hint(const char* normalized,
		const char** cls,
		const char** rir,
		const char** reason,
		const char** confidence)
{
	const char* guessed_rir = wc_guess_rir(normalized);
	if (guessed_rir && strcmp(guessed_rir, "unknown") != 0) {
		*cls = "allocated";
		*rir = guessed_rir;
		*reason = "RIR_HINT_FROM_EXISTING_GUESS";
		*confidence = "medium";
		return;
	}
	*cls = "unknown";
	*rir = "unknown";
	*reason = "NO_RIR_HINT";
	*confidence = "low";
}

static int wc_preclass_is_v6_loopback(const struct in6_addr* addr6)
{
	if (!addr6)
		return 0;
	for (int i = 0; i < 15; ++i) {
		if (addr6->s6_addr[i] != 0)
			return 0;
	}
	return addr6->s6_addr[15] == 1;
}

void wc_preclass_classify_ip(const char* normalized,
		const char** family,
		const char** cls,
		const char** rir,
		const char** reason,
		const char** confidence)
{
	if (!normalized || !family || !cls || !rir || !reason || !confidence)
		return;

	struct in_addr addr4;
	if (inet_pton(AF_INET, normalized, &addr4) == 1) {
		unsigned char b[4];
		memcpy(b, &addr4, sizeof(b));
		*family = "v4";

		if (b[0] == 255 && b[1] == 255 && b[2] == 255 && b[3] == 255) {
			*cls = "special";
			*rir = "none";
			*reason = "V4_LIMITED_BROADCAST_255_255_255_255";
			*confidence = "high";
			return;
		}
		if (b[0] >= 240) {
			*cls = "reserved";
			*rir = "none";
			*reason = "V4_FUTURE_USE_240_4";
			*confidence = "high";
			return;
		}
		if (b[0] == 0) {
			*cls = "special";
			*rir = "none";
			*reason = "V4_THIS_NETWORK_0_8";
			*confidence = "high";
			return;
		}
		if (b[0] == 10) {
			*cls = "special";
			*rir = "none";
			*reason = "V4_PRIVATE_10_8";
			*confidence = "high";
			return;
		}
		if (b[0] == 127) {
			*cls = "special";
			*rir = "none";
			*reason = "V4_LOOPBACK_127_8";
			*confidence = "high";
			return;
		}
		if (b[0] == 169 && b[1] == 254) {
			*cls = "special";
			*rir = "none";
			*reason = "V4_LINK_LOCAL_169_254_16";
			*confidence = "high";
			return;
		}
		if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) {
			*cls = "special";
			*rir = "none";
			*reason = "V4_PRIVATE_172_16_12";
			*confidence = "high";
			return;
		}
		if (b[0] == 192 && b[1] == 168) {
			*cls = "special";
			*rir = "none";
			*reason = "V4_PRIVATE_192_168_16";
			*confidence = "high";
			return;
		}
		if (b[0] >= 224 && b[0] <= 239) {
			*cls = "special";
			*rir = "none";
			*reason = "V4_MULTICAST_224_4";
			*confidence = "high";
			return;
		}

		wc_preclass_set_allocated_hint(normalized, cls, rir, reason, confidence);
		return;
	}

	struct in6_addr addr6;
	if (inet_pton(AF_INET6, normalized, &addr6) == 1) {
		const unsigned char* b = addr6.s6_addr;
		*family = "v6";

		if (wc_preclass_is_v6_loopback(&addr6)) {
			*cls = "special";
			*rir = "none";
			*reason = "V6_LOOPBACK_1";
			*confidence = "high";
			return;
		}
		if ((b[0] & 0xFE) == 0xFC) {
			*cls = "special";
			*rir = "none";
			*reason = "V6_UNIQUE_LOCAL_FC00_7";
			*confidence = "high";
			return;
		}
		if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) {
			*cls = "special";
			*rir = "none";
			*reason = "V6_LINK_LOCAL_FE80_10";
			*confidence = "high";
			return;
		}
		if (b[0] == 0xFF) {
			*cls = "special";
			*rir = "none";
			*reason = "V6_MULTICAST_FF00_8";
			*confidence = "high";
			return;
		}
		if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8) {
			*cls = "special";
			*rir = "none";
			*reason = "V6_DOCUMENTATION_2001_DB8_32";
			*confidence = "high";
			return;
		}
		if ((b[0] & 0xE0) == 0x20) {
			*cls = "allocated";
			*reason = "V6_GLOBAL_UNICAST_2000_3";
			const char* guessed_rir = wc_guess_rir(normalized);
			if (guessed_rir && strcmp(guessed_rir, "unknown") != 0) {
				*rir = guessed_rir;
				*confidence = "medium";
			} else {
				*rir = "unknown";
				*confidence = "low";
			}
			return;
		}

		*cls = "unknown";
		*rir = "unknown";
		*reason = "V6_NO_RIR_HINT";
		*confidence = "low";
	}
}
