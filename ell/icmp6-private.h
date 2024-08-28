/*
 * Embedded Linux library
 * Copyright (C) 2020  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

struct route_info {
	uint8_t address[16];
	bool onlink : 1;
	uint8_t prefix_len;
	uint8_t preference;
	uint32_t valid_lifetime;
};

struct autoconf_prefix_info {
	uint8_t prefix[8];
	uint32_t preferred_lifetime;
	uint32_t valid_lifetime;
};

struct dns_info {
	uint8_t address[16];
	uint32_t lifetime;
};

struct domain_info {
	char *domain;
	uint32_t lifetime;
};

struct l_icmp6_router {
	uint8_t address[16];
	bool managed : 1;
	bool other : 1;
	uint8_t pref;
	uint64_t start_time;
	uint16_t lifetime;
	uint32_t mtu;
	uint32_t max_rtr_adv_interval_ms;
	uint32_t n_routes;
	struct route_info *routes;
	uint32_t n_ac_prefixes;
	struct autoconf_prefix_info *ac_prefixes;
	uint32_t n_dns;
	struct dns_info *dns_list;
	uint32_t n_domains;
	struct domain_info *domains;
};

struct l_icmp6_router *_icmp6_router_new();
void _icmp6_router_free(struct l_icmp6_router *r);
struct l_icmp6_router *_icmp6_router_parse(const struct nd_router_advert *ra,
						size_t len,
						const uint8_t src[static 16],
						uint64_t timestamp);
