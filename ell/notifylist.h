/*
 * Embedded Linux library
 * Copyright (C) 2024  Cruise, LLC
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef __ELL_NOTIFYLIST_H
#define __ELL_NOTIFYLIST_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

struct l_notifylist_entry;

typedef void (*l_notifylist_destroy_func_t)(void *data);
typedef bool (*l_notifylist_entry_matches_func_t)(
				const struct l_notifylist_entry *,
				const void *);

struct l_notifylist_entry {
	unsigned int id;
	void *notify_data;
	l_notifylist_destroy_func_t destroy;
};

struct l_notifylist_ops {
	void (*free_entry)(struct l_notifylist_entry *entry);
	void (*notify)(const struct l_notifylist_entry *entry,
						int type, va_list args);
};

struct l_notifylist *l_notifylist_new(const struct l_notifylist_ops *ops);
void l_notifylist_free(struct l_notifylist *list);
uint32_t l_notifylist_add(struct l_notifylist *list,
					struct l_notifylist_entry *entry);
bool l_notifylist_remove(struct l_notifylist *list, uint32_t id);
bool l_notifylist_notify(struct l_notifylist *list, int type, ...);
bool l_notifylist_notify_matches(struct l_notifylist *list,
				l_notifylist_entry_matches_func_t match_func,
				const void *match_data, int type, ...);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_NOTIFYLIST_H */
