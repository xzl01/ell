/*
 * Embedded Linux library
 * Copyright (C) 2024  Cruise, LLC
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "private.h"
#include "queue.h"
#include "notifylist.h"
#include "useful.h"

struct l_notifylist {
	uint32_t next_id;
	struct l_queue *entries;
	bool in_notify : 1;
	bool stale_entries : 1;
	bool pending_destroy : 1;
	const struct l_notifylist_ops *ops;
};

static bool __notifylist_entry_match(const void *a, const void *b)
{
	const struct l_notifylist_entry *entry = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return entry->id == id;
}

static void __notifylist_entry_free(struct l_notifylist *list,
						struct l_notifylist_entry *e)
{
	if (e->destroy)
		e->destroy(e->notify_data);

	list->ops->free_entry(e);
}

static void __notifylist_clear(struct l_notifylist *list)
{
	struct l_notifylist_entry *entry;

	while ((entry = l_queue_pop_head(list->entries)))
		__notifylist_entry_free(list, entry);
}

static void __notifylist_prune_stale(struct l_notifylist *list)
{
	struct l_notifylist_entry *e;

	while ((e = l_queue_remove_if(list->entries, __notifylist_entry_match,
							L_UINT_TO_PTR(0))))
		__notifylist_entry_free(list, e);

	list->stale_entries = false;
}

static void __notifylist_destroy(struct l_notifylist *list)
{
	__notifylist_clear(list);
	l_queue_destroy(list->entries, NULL);
	list->entries = NULL;

	l_free(list);
}

static void __notifylist_notify(struct l_notifylist *list,
				l_notifylist_entry_matches_func_t match_func,
				const void *match_data,
				int type, va_list args)
{
	const struct l_queue_entry *entry = l_queue_get_entries(list->entries);

	list->in_notify = true;

	for (; entry; entry = entry->next) {
		const struct l_notifylist_entry *e = entry->data;
		va_list copy;

		if (e->id == 0)
			continue;

		if (match_func && !match_func(e, match_data))
			continue;

		va_copy(copy, args);
		list->ops->notify(e, type, copy);
		va_end(copy);

		if (list->pending_destroy)
			break;
	}

	list->in_notify = false;

	if (list->pending_destroy)
		__notifylist_destroy(list);
	else if (list->stale_entries)
		__notifylist_prune_stale(list);
}

LIB_EXPORT struct l_notifylist *l_notifylist_new(
					const struct l_notifylist_ops *ops)
{
	struct l_notifylist *list = l_new(struct l_notifylist, 1);

	list->entries = l_queue_new();
	list->ops = ops;
	list->next_id = 1;

	return list;
}

LIB_EXPORT uint32_t l_notifylist_add(struct l_notifylist *list,
					struct l_notifylist_entry *entry)
{
	if (!list)
		return 0;

	entry->id = list->next_id++;

	if (!list->next_id)
		list->next_id = 1;

	l_queue_push_tail(list->entries, entry);

	return entry->id;
}

LIB_EXPORT bool l_notifylist_remove(struct l_notifylist *list, uint32_t id)
{
	struct l_notifylist_entry *entry;

	if (!list)
		return false;

	if (list->in_notify) {
		entry = l_queue_find(list->entries, __notifylist_entry_match,
							L_UINT_TO_PTR(id));
		if (!entry)
			return false;

		entry->id = 0;	/* Mark stale */
		list->stale_entries = true;

		return true;
	}

	entry = l_queue_remove_if(list->entries, __notifylist_entry_match,
							L_UINT_TO_PTR(id));
	if (!entry)
		return false;

	__notifylist_entry_free(list, entry);

	return true;
}

LIB_EXPORT void l_notifylist_free(struct l_notifylist *list)
{
	if (!list)
		return;

	if (list->in_notify) {
		list->pending_destroy = true;
		return;
	}

	__notifylist_destroy(list);
}

LIB_EXPORT bool l_notifylist_notify(struct l_notifylist *list,
							int type, ...)
{
	va_list args;

	if (!list)
		return false;

	va_start(args, type);
	__notifylist_notify(list, NULL, NULL, type, args);
	va_end(args);

	return true;
}

LIB_EXPORT bool l_notifylist_notify_matches(struct l_notifylist *list,
				l_notifylist_entry_matches_func_t match_func,
				const void *match_data, int type, ...)
{
	va_list args;

	if (!list)
		return false;

	if (!match_func)
		return false;

	va_start(args, type);
	__notifylist_notify(list, match_func, match_data, type, args);
	va_end(args);

	return true;
}
