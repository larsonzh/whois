#include <ctype.h>
#include <stdint.h>
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
#include "wc/wc_preclass_table.h"
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

static const char* wc_preclass_observe_reason_code(const char* reason)
{
	if (!reason || !*reason)
		return "NON_IP_INPUT";
	return reason;
}

static const char* wc_preclass_observe_reason_key(const char* reason)
{
	static const char* prefix = "PRECLASS_REASON_";
	const size_t prefix_len = strlen(prefix);
	if (!reason || !*reason)
		return "NON_IP_INPUT";
	if (strncmp(reason, prefix, prefix_len) == 0 && reason[prefix_len] != '\0')
		return reason + prefix_len;
	return reason;
}

static const char* wc_preclass_observe_confidence_code(const char* confidence)
{
	if (!confidence || !*confidence)
		return "C0";
	if (strcmp(confidence, "high") == 0)
		return "C3";
	if (strcmp(confidence, "medium") == 0)
		return "C2";
	if (strcmp(confidence, "low") == 0)
		return "C1";
	return "C0";
}

static int wc_preclass_observe_confidence_rank(const char* confidence)
{
	if (!confidence || !*confidence)
		return 0;
	if (strcmp(confidence, "high") == 0)
		return 3;
	if (strcmp(confidence, "medium") == 0)
		return 2;
	if (strcmp(confidence, "low") == 0)
		return 1;
	return 0;
}

void wc_preclass_observation_codes(const char* reason,
		const char* confidence,
		const char** reason_code,
		const char** reason_key,
		const char** confidence_code,
		int* confidence_rank)
{
	if (reason_code)
		*reason_code = wc_preclass_observe_reason_code(reason);
	if (reason_key)
		*reason_key = wc_preclass_observe_reason_key(reason);
	if (confidence_code)
		*confidence_code = wc_preclass_observe_confidence_code(confidence);
	if (confidence_rank)
		*confidence_rank = wc_preclass_observe_confidence_rank(confidence);
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

static uint64_t wc_preclass_read_be64(const unsigned char* bytes)
{
	if (!bytes)
		return 0;
	return (((uint64_t)bytes[0]) << 56) |
		(((uint64_t)bytes[1]) << 48) |
		(((uint64_t)bytes[2]) << 40) |
		(((uint64_t)bytes[3]) << 32) |
		(((uint64_t)bytes[4]) << 24) |
		(((uint64_t)bytes[5]) << 16) |
		(((uint64_t)bytes[6]) << 8) |
		((uint64_t)bytes[7]);
}

static const char* wc_preclass_class_name(uint8_t class_id)
{
	switch (class_id) {
		case 0u: return "unknown";
		case 1u: return "allocated";
		case 2u: return "legacy";
		case 3u: return "reserved";
		case 4u: return "special";
		case 5u: return "unallocated";
		default: return "unknown";
	}
}

static const char* wc_preclass_rir_name(uint8_t rir_id)
{
	switch (rir_id) {
		case 0u: return "unknown";
		case 1u: return "none";
		case 2u: return "apnic";
		case 3u: return "arin";
		case 4u: return "ripe";
		case 5u: return "afrinic";
		case 6u: return "lacnic";
		default: return "unknown";
	}
}

static const char* wc_preclass_confidence_name(uint8_t confidence_id)
{
	switch (confidence_id) {
		case 0u: return "low";
		case 1u: return "medium";
		case 2u: return "high";
		default: return "low";
	}
}

static const char* wc_preclass_reason_name(uint16_t reason_id)
{
	switch (reason_id) {
		case 1001u: return "V4_ALLOCATED_REGISTRY";
		case 1002u: return "V4_LEGACY_REGISTRY";
		case 1003u: return "V4_RESERVED_REGISTRY";
		case 1099u: return "V4_UNKNOWN_REGISTRY";
		case 2001u: return "V6_GLOBAL_UNICAST_2000_3";
		case 2002u: return "V6_UNIQUE_LOCAL_FC00_7";
		case 2003u: return "V6_LINK_LOCAL_FE80_10";
		case 2004u: return "V6_MULTICAST_FF00_8";
		case 2005u: return "V6_RESERVED_IETF";
		case 2099u: return "V6_UNKNOWN_REGISTRY";
		default: return "PRECLASS_REASON_UNKNOWN";
	}
}

static int wc_preclass_lookup_row_v4(uint32_t addr, const wc_preclass_table_row_t** out_row)
{
	size_t i;

	if (!out_row)
		return 0;
	*out_row = NULL;

	for (i = 0; i < wc_preclass_table_count; ++i) {
		const wc_preclass_table_row_t* row = &wc_preclass_table[i];
		uint8_t prefix_len;
		uint32_t row_addr;
		uint32_t mask;

		if (row->family == 6u)
			break;
		if (row->family != 4u)
			continue;

		prefix_len = row->prefix_len;
		if (prefix_len > 32u)
			continue;

		row_addr = (uint32_t)(row->addr_lo & 0xFFFFFFFFu);
		if (prefix_len == 0u) {
			*out_row = row;
			return 1;
		}

		mask = (prefix_len == 32u)
			? 0xFFFFFFFFu
			: (0xFFFFFFFFu << (32u - prefix_len));
		if ((addr & mask) == (row_addr & mask)) {
			*out_row = row;
			return 1;
		}
	}

	return 0;
}

static int wc_preclass_lookup_row_v6(uint64_t hi,
		uint64_t lo,
		const wc_preclass_table_row_t** out_row)
{
	size_t i;

	if (!out_row)
		return 0;
	*out_row = NULL;

	for (i = 0; i < wc_preclass_table_count; ++i) {
		const wc_preclass_table_row_t* row = &wc_preclass_table[i];
		uint8_t prefix_len;

		if (row->family != 6u)
			continue;

		prefix_len = row->prefix_len;
		if (prefix_len > 128u)
			continue;

		if (prefix_len == 0u) {
			*out_row = row;
			return 1;
		}

		if (prefix_len <= 64u) {
			uint64_t mask_hi = (prefix_len == 64u)
				? 0xFFFFFFFFFFFFFFFFULL
				: (0xFFFFFFFFFFFFFFFFULL << (64u - prefix_len));
			if ((hi & mask_hi) == (row->addr_hi & mask_hi)) {
				*out_row = row;
				return 1;
			}
			continue;
		}

		if (hi != row->addr_hi)
			continue;

		uint8_t rem = (uint8_t)(prefix_len - 64u);
		uint64_t mask_lo = (rem == 64u)
			? 0xFFFFFFFFFFFFFFFFULL
			: (0xFFFFFFFFFFFFFFFFULL << (64u - rem));
		if ((lo & mask_lo) == (row->addr_lo & mask_lo)) {
			*out_row = row;
			return 1;
		}
	}

	return 0;
}

static void wc_preclass_assign_from_row(const wc_preclass_table_row_t* row,
		const char** cls,
		const char** rir,
		const char** reason,
		const char** confidence)
{
	if (!row || !cls || !rir || !reason || !confidence)
		return;
	*cls = wc_preclass_class_name(row->class_id);
	*rir = wc_preclass_rir_name(row->rir_id);
	*reason = wc_preclass_reason_name(row->reason_id);
	*confidence = wc_preclass_confidence_name(row->confidence_id);
}

static int wc_preclass_lookup_table(const char* normalized,
		const char** family,
		const char** cls,
		const char** rir,
		const char** reason,
		const char** confidence)
{
	struct in_addr addr4;
	struct in6_addr addr6;

	if (!normalized || !family || !cls || !rir || !reason || !confidence)
		return 0;

	if (inet_pton(AF_INET, normalized, &addr4) == 1) {
		const wc_preclass_table_row_t* row;
		unsigned char b[4];
		uint32_t ip;
		memcpy(b, &addr4, sizeof(b));
		ip = (((uint32_t)b[0]) << 24) |
			(((uint32_t)b[1]) << 16) |
			(((uint32_t)b[2]) << 8) |
			((uint32_t)b[3]);
		if (!wc_preclass_lookup_row_v4(ip, &row))
			return 0;
		*family = "v4";
		wc_preclass_assign_from_row(row, cls, rir, reason, confidence);
		return 1;
	}

	if (inet_pton(AF_INET6, normalized, &addr6) == 1) {
		const wc_preclass_table_row_t* row;
		const unsigned char* b = addr6.s6_addr;
		uint64_t hi = wc_preclass_read_be64(b);
		uint64_t lo = wc_preclass_read_be64(b + 8);
		if (!wc_preclass_lookup_row_v6(hi, lo, &row))
			return 0;
		*family = "v6";
		wc_preclass_assign_from_row(row, cls, rir, reason, confidence);
		return 1;
	}

	return 0;
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

	*family = "non-ip";
	*cls = "unknown";
	*rir = "unknown";
	*reason = "NON_IP_INPUT";
	*confidence = "low";

	(void)wc_preclass_lookup_table(normalized,
		family,
		cls,
		rir,
		reason,
		confidence);

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

		if (strcmp(*cls, "unknown") == 0)
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

		if (strcmp(*cls, "unknown") == 0) {
			*rir = "unknown";
			*reason = "V6_NO_RIR_HINT";
			*confidence = "low";
		}
		return;
	}
}
