/*
 * Embedded Linux library
 * Copyright (C) 2018  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <sys/socket.h>
#include <linux/if_arp.h>

#include <ell/ell.h>

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void signal_handler(uint32_t signo, void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_info("Terminate");
		l_main_quit();
		break;
	}
}

static void event_handler(struct l_dhcp_client *client,
					enum l_dhcp_client_event event,
					void *userdata)
{
	const struct l_dhcp_lease *lease = l_dhcp_client_get_lease(client);
	char *ip = l_dhcp_lease_get_address(lease);
	char *netmask = l_dhcp_lease_get_netmask(lease);
	char *gw = l_dhcp_lease_get_gateway(lease);
	uint32_t lifetime = l_dhcp_lease_get_lifetime(lease);
	char **dns = l_dhcp_lease_get_dns(lease);

	l_info("Lease Obtained:");
	l_info("\tIP: %s, Netmask: %s, Gateway: %s", ip, netmask, gw);
	l_info("Lifetime: %u seconds", lifetime);
	if (dns) {
		char *dns_concat = l_strjoinv(dns, ',');
		l_info("DNS List: %s", dns_concat);
		l_free(dns_concat);
		l_strfreev(dns);
	} else
		l_info("No DNS information obtained");

	l_free(ip);
	l_free(netmask);
	l_free(gw);
}

int main(int argc, char *argv[])
{
	struct l_dhcp_client *client;
	int ifindex;
	uint8_t mac[6];

	if (argc < 2) {
                printf("Usage: %s <interface index>\n", argv[0]);
                exit(0);
        }

	ifindex = atoi(argv[1]);

	if (!l_net_get_mac_address(ifindex, mac)) {
		printf("Unable to get address from interface %d\n", ifindex);
		exit(0);
	}

	if (!l_main_init())
		return -1;

	l_log_set_stderr();
	l_debug_enable("*");

	client = l_dhcp_client_new(ifindex);
	l_dhcp_client_set_address(client, ARPHRD_ETHER, mac, 6);
	l_dhcp_client_set_event_handler(client, event_handler, NULL, NULL);
	l_dhcp_client_set_debug(client, do_debug, "[DHCP] ", NULL, L_LOG_DEBUG);
	l_dhcp_client_start(client);

	l_main_run_with_signal(signal_handler, NULL);

	l_dhcp_client_destroy(client);
	l_main_exit();

	return 0;
}
