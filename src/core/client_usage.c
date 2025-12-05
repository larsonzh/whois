// SPDX-License-Identifier: GPL-3.0-or-later
// Client usage helpers: server catalog & alias resolution.

#include <stdio.h>
#include <string.h>

#include "wc/wc_client_usage.h"

static const wc_client_server_entry_t k_whois_servers[] = {
    {"arin", "whois.arin.net", "American Registry for Internet Numbers"},
    {"apnic", "whois.apnic.net", "Asia-Pacific Network Information Centre"},
    {"ripe", "whois.ripe.net", "RIPE Network Coordination Centre"},
    {"lacnic", "whois.lacnic.net",
        "Latin America and Caribbean Network Information Centre"},
    {"afrinic", "whois.afrinic.net", "African Network Information Centre"},
    {"verisign", "whois.verisign-grs.com", "Verisign gTLD registry"},
    {"iana", "whois.iana.org", "Internet Assigned Numbers Authority"},
    {NULL, NULL, NULL}
};

void wc_client_print_server_catalog(void)
{
    printf("Available whois servers:\n\n");
    for (int i = 0; k_whois_servers[i].alias != NULL; ++i) {
        printf("  %-12s - %s\n",
            k_whois_servers[i].alias,
            k_whois_servers[i].description);
        printf("            Domain: %s\n\n", k_whois_servers[i].domain);
    }
}

const wc_client_server_entry_t* wc_client_server_catalog(void)
{
    return k_whois_servers;
}

const char* wc_client_find_server_domain(const char* alias)
{
    if (!alias || !*alias)
        return NULL;
    for (int i = 0; k_whois_servers[i].alias != NULL; ++i) {
        if (strcmp(alias, k_whois_servers[i].alias) == 0)
            return k_whois_servers[i].domain;
    }
    return NULL;
}
