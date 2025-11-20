#pragma once

// Default configuration values shared between whois_client.c and
// core/meta helpers. Keep these in sync with RELEASE_NOTES and docs
// if behavior changes.

#define WC_DEFAULT_WHOIS_PORT 43
#define WC_DEFAULT_BUFFER_SIZE 524288
#define WC_DEFAULT_MAX_RETRIES 2
#define WC_DEFAULT_TIMEOUT_SEC 5
#define WC_DEFAULT_DNS_CACHE_SIZE 10
#define WC_DEFAULT_CONNECTION_CACHE_SIZE 5
#define WC_DEFAULT_CACHE_TIMEOUT 300
#define WC_DEFAULT_DEBUG_LEVEL 0
#define WC_DEFAULT_MAX_REDIRECTS 5
