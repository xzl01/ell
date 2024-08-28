/*
 * Embedded Linux library
 * Copyright (C) 2011-2014  Intel Corporation
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __ELL_NETLINK_H
#define __ELL_NETLINK_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*l_netlink_debug_func_t) (const char *str, void *user_data);

typedef void (*l_netlink_command_func_t) (int error,
						uint16_t type, const void *data,
						uint32_t len, void *user_data);
typedef void (*l_netlink_notify_func_t) (uint16_t type, const void *data,
						uint32_t len, void *user_data);
typedef void (*l_netlink_destroy_func_t) (void *user_data);

struct l_netlink;

struct l_netlink *l_netlink_new(int protocol);
void l_netlink_destroy(struct l_netlink *netlink);

unsigned int l_netlink_send(struct l_netlink *netlink,
			uint16_t type, uint16_t flags, const void *data,
			uint32_t len, l_netlink_command_func_t function,
			void *user_data, l_netlink_destroy_func_t destroy);
bool l_netlink_cancel(struct l_netlink *netlink, unsigned int id);

unsigned int l_netlink_register(struct l_netlink *netlink,
			uint32_t group, l_netlink_notify_func_t function,
			void *user_data, l_netlink_destroy_func_t destroy);
bool l_netlink_unregister(struct l_netlink *netlink, unsigned int id);

bool l_netlink_set_debug(struct l_netlink *netlink,
			l_netlink_debug_func_t function,
			void *user_data, l_netlink_destroy_func_t destroy);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_NETLINK_H */
