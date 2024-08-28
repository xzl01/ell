/*
 * Embedded Linux library
 * Copyright (C) 2022  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

struct l_rtnl_route {
	uint8_t family;
	uint8_t scope;
	uint8_t protocol;
	union {
		struct in6_addr in6_addr;
		struct in_addr in_addr;
	} gw;
	union {
		struct in6_addr in6_addr;
		struct in_addr in_addr;
	} dst;
	uint8_t dst_prefix_len;
	union {
		struct in6_addr in6_addr;
		struct in_addr in_addr;
	} prefsrc;
	uint32_t lifetime;
	uint64_t expiry_time;
	uint32_t mtu;
	uint32_t priority;
	uint8_t preference;
};
