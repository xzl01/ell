/*
 * Embedded Linux library
 * Copyright (C) 2020  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

char *net_domain_name_parse(const uint8_t *raw, size_t raw_len);
char **net_domain_list_parse(const uint8_t *raw, size_t raw_len, bool padded);

static inline const void *net_prefix_from_ipv6(const uint8_t *address,
						uint8_t prefix_len)
{
	uint8_t last_byte = prefix_len / 8;
	uint8_t bits = prefix_len & 7;
	static uint8_t prefix[16];

	memcpy(prefix, address, last_byte);

	if (prefix_len & 7) {
		prefix[last_byte] = address[last_byte] & (0xff00 >> bits);
		last_byte++;
	}

	memset(prefix + last_byte, 0, 16 - last_byte);
	return prefix;
}
